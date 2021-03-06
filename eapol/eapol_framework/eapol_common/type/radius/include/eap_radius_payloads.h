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

#if !defined(_EAP_RADIUS_RESULT_H_)
#define _EAP_RADIUS_RESULT_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_PAYLOADS_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_PAYLOADS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_PAYLOADS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_radius_header.h"
#include "eap_radius_attribute_header.h"
#include "eap_core_map.h"


class EAP_CLASS_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_radius_variable_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_data;

	eap_diameter_avp_code_c m_payload_type;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H virtual ~eap_radius_variable_data_c();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_radius_variable_data_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_status_e set_buffer(
		const eap_diameter_avp_code_c current_payload,
		const u8_t * const buffer,
		const u32_t buffer_length,
		const bool free_buffer,
		const bool is_writable);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_status_e add_data(
		const u8_t * const buffer,
		const u32_t buffer_length);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H u8_t * get_data(const u32_t data_length) const;

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_variable_data_c * get_payload_buffer();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_diameter_avp_code_c get_payload_type() const;

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H void set_payload_type(const eap_diameter_avp_code_c type);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_radius_variable_data_c * copy() const;

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H  void object_increase_reference_count();

	//--------------------------------------------------
}; // class eap_radius_variable_data_c


//--------------------------------------------------


// 
class EAP_CLASS_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_radius_payloads_c
: public abs_eap_core_map_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	/// This stores  objects using eap_variable_data selector.
	eap_core_map_c<eap_radius_variable_data_c, abs_eap_core_map_c, eap_variable_data_c> m_payload_map;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H virtual ~eap_radius_payloads_c();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_radius_payloads_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_radius_variable_data_c * get_payload(
		const eap_diameter_avp_code_c current_payload);

	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_status_e add_payload(
		const eap_diameter_avp_code_c current_payload,
		const u8_t * const data,
		const u32_t data_length,
		const bool free_buffer,
		const bool is_writable,
		const bool fragments_allowed);

	/**
	 * This function parses the payloads starting from specified payload (p_payload).
	 * Function parses all payloads from the buffer.
	 * Payloads are stored to p_radius_payloads.
	 * @return If the length of the buffer and sum of the length of all payloads does not match
	 * function returns eap_status_header_corrupted.
	 * Also error is returned when illegal payload attribute is recognised.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_status_e parse_radius_payload(
		const eap_radius_attribute_header_c * const p_payload, ///< This is the start of the buffer and the first parsed payload.
		u32_t * const buffer_length ///< This is the length of the buffer. This must match with the length of all payloads.
		);

	/**
	 * This function parses each payload attributes.
	 * @return If payload attribute is illegal function returns eap_status_header_corrupted.
	 * If payload attribute is unknown function returns eap_status_unsupported_payload.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H eap_status_e parse_generic_payload(
		const eap_diameter_avp_code_c current_payload, ///< This is the type of current payload attribute.
		const eap_radius_attribute_header_c * const payload ///< This is the current parsed payload.
		);


	EAP_FUNC_VISIBILITY_EAP_RADIUS_PAYLOADS_H bool get_is_valid() const;

	//--------------------------------------------------
}; // class eap_radius_payloads_c


#endif //#if !defined(_EAP_RADIUS_RESULT_H_)

//--------------------------------------------------



// End.
