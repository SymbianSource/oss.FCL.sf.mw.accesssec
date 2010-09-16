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

#ifndef EAP_AM_TYPE_SECURID_H
#define EAP_AM_TYPE_SECURID_H

#include "abs_eap_am_type_securid.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_SECURID_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SECURID_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SECURID_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_SECURID_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SECURID_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SECURID_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SECURID_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SECURID_H 
#endif
// End: added by script change_export_macros.sh.


/// This class is interface to adaptation module of EAP SecurID
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SECURID_H eap_am_type_securid_c
{
private:

	abs_eap_am_type_securid_c *m_am_partner;
	abs_eap_am_tools_c *m_am_tools;

	bool m_is_valid;

protected:

public:

	virtual ~eap_am_type_securid_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	eap_am_type_securid_c(abs_eap_am_tools_c * const tools /*, abs_eap_am_type_securid_c * const partner */)
	: m_am_partner(0)
	, m_am_tools(tools)
	, m_is_valid(false)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		set_is_valid();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	virtual eap_status_e shutdown() = 0;

	/** Function returns partner object of adaptation module of EAP SecurID.
	 *  Partner object is the EAP SecurID object.
	 */
	abs_eap_am_type_securid_c * const get_am_partner()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return m_am_partner;
	}

	/** Function sets partner object of adaptation module of SECURID.
	 *  Partner object is the SECURID object.
	 */
	void set_am_partner(abs_eap_am_type_securid_c * const partner)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		m_am_partner = partner;
	}

	void set_is_valid()
	{
		m_is_valid = true;
	}

	bool get_is_valid()
	{
		return m_is_valid;
	}

	virtual eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	virtual eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data) = 0;

	virtual eap_status_e configure() = 0;

	virtual eap_status_e reset() = 0;

	virtual eap_status_e show_identity_query_dialog(eap_type_value_e eap_type, eap_variable_data_c * const identity) = 0;

	virtual eap_status_e show_passcode_query_dialog(eap_variable_data_c * const passcode,
													bool is_first_query) = 0;

	virtual eap_status_e show_pincode_query_dialog(eap_variable_data_c * const passcode,
												   eap_variable_data_c * const pincode,
												   bool is_first_query) = 0;

	virtual eap_status_e show_gtc_query_dialog(eap_variable_data_c * const passcode,
												   const u8_t * const message,
												   u32_t message_length,
												   bool is_first_query) = 0;

	virtual eap_status_e read_auth_failure_string(eap_variable_data_c * const string) = 0;

	/// This function queries unique key for memory store object of this access.
	virtual eap_status_e get_memory_store_key(eap_variable_data_c * const memory_store_key) = 0;
};

EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SECURID_H  eap_am_type_securid_c *new_eap_am_type_securid(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const eap_type_value_e eap_type,
	const eap_am_network_id_c * const receive_network_id);

#endif // EAP_AM_TYPE_SECURID_H
