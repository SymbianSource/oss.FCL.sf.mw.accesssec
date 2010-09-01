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
* %version: 12 %
*/

#ifndef EAP_AM_TYPE_LEAP_H
#define EAP_AM_TYPE_LEAP_H

//  INCLUDES
#include "abs_eap_am_type_leap.h"

// CLASS DECLARATION

/// This class is interface to adaptation module of LEAP.
class EAP_EXPORT eap_am_type_leap_c
{
	public: // Methods

		// Constructors and destructor

		eap_am_type_leap_c(abs_eap_am_tools_c * const tools)
		: m_am_partner(0)
		, m_am_tools(tools)
		{
			EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		}

		virtual ~eap_am_type_leap_c()
		{
			EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		}

		virtual eap_status_e shutdown() = 0;

		/** Function returns partner object of adaptation module of LEAP.
		 *  Partner object is the LEAP object.
		 */
		abs_eap_am_type_leap_c * const get_am_partner()
		{
			EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return m_am_partner;
		}

		/** Function sets partner object of adaptation module of LEAP.
		 *  Partner object is the LEAP object.
		 */
		void set_am_partner(abs_eap_am_type_leap_c * const partner)
		{
			EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			m_am_partner = partner;
		}

		virtual void set_is_valid() = 0;

		virtual bool get_is_valid() = 0;

		virtual eap_status_e type_configure_read(
			const eap_configuration_field_c * const field,
			eap_variable_data_c * const data) = 0;

		virtual eap_status_e type_configure_write(
			const eap_configuration_field_c * const field,
			eap_variable_data_c * const data) = 0;

		virtual eap_status_e configure() = 0;

		virtual eap_status_e reset() = 0;

		virtual eap_status_e show_username_password_dialog(
			eap_variable_data_c &username_utf8,
			eap_variable_data_c &password_utf8,
			bool &password_prompt_enabled,
			bool is_identity_query) = 0;

		virtual eap_status_e read_auth_failure_string(eap_variable_data_c &string) = 0;

		/// This function queries unique key for memory store object of this access.
		virtual eap_status_e get_memory_store_key(eap_variable_data_c * const memory_store_key) = 0;
		
		/**
		 * Returns true if the full authenticated session is valid.
		 * It finds the difference between current time and the 
		 * last full authentication time. If the difference is less than the
		 * Maximum Session Validity Time, then session is valid, returns true.
		 * Otherwise returns false. 
		 * Full authentication (using pw query) should be done if the session is not valid.
		 */
		virtual bool is_session_valid() = 0;
		
		/**
		 * Stores current universal time as the the full authentication time
		 * in the database.
		 * Returns appropriate error if storing fails. eap_status_ok for successful storing.
		 */
		virtual eap_status_e store_authentication_time() = 0;

	private: // Data

		abs_eap_am_type_leap_c * m_am_partner;

		abs_eap_am_tools_c * m_am_tools;

protected:

};


EAP_C_FUNC_IMPORT  eap_am_type_leap_c *new_eap_am_type_leap(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id);

#endif // EAP_AM_TYPE_LEAP_H

// End of File
