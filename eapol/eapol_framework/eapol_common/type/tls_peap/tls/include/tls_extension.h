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
* %version: 9.1.3 %
*/

#if !defined(_TLS_EXTENSION_H_)
#define _TLS_EXTENSION_H_

#if defined(USE_EAP_TLS_SESSION_TICKET)

#include "eap_tools.h"
#include "eap_array.h"
#include "eap_variable_data.h"
#if defined(USE_FAST_EAP_TYPE)
#include "eap_fast_tlv_header.h"
#endif //#if defined(USE_FAST_EAP_TYPE)

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_EXTENSION_H)
	#define EAP_CLASS_VISIBILITY_TLS_EXTENSION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_EXTENSION_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_EXTENSION_H 
	#define EAP_FUNC_EXPORT_TLS_EXTENSION_H 
	#define EAP_C_FUNC_EXPORT_TLS_EXTENSION_H 
#elif defined(EAP_EXPORT_TLS_EXTENSION_H)
	#define EAP_CLASS_VISIBILITY_TLS_EXTENSION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_EXTENSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_EXTENSION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_EXTENSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_EXTENSION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_EXTENSION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_EXTENSION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_EXTENSION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_EXTENSION_H 
	#define EAP_C_FUNC_EXPORT_TLS_EXTENSION_H 
#endif
// End: added by script change_export_macros.sh.

/** @file */

/**
 * This is enumeration of TLS competion actions.
 */
enum tls_extension_type_e
{
	tls_extension_type_none = 65535,               ///< Initialization value means no type.
	tls_extension_type_server_name = 0,            ///< Server Name Indication, see RFC 4366
	tls_extension_type_max_frame_length = 1,       ///< Maximum Fragment Length Negotiation, see RFC 4366
	tls_extension_type_client_certificate_url = 2, ///< Client Certificate URLs, see RFC 4366
	tls_extension_type_trusted_ca_keys = 3,        ///< Trusted CA Indication, see RFC 4366
	tls_extension_type_truncated_hmac = 4,         ///< Truncated HMAC, see RFC 4366
	tls_extension_type_status_request = 5,         ///< Certificate Status Request, see RFC 4366
	tls_extension_type_session_ticket = 35,        ///< Session Ticket, see RFC 4507
};

//----------------------------------------------------------------------------


/// This class defines one TLS completion action.
class EAP_CLASS_VISIBILITY_TLS_EXTENSION_H tls_extension_c
: public eap_variable_data_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This variable stores the lifetime hint of extension.
	u32_t m_lifetime_hint;

	/// This variable stores the type of extension.
	tls_extension_type_e m_type;

#if defined(USE_FAST_EAP_TYPE)
	/// This variable stores the PAC-Type for fast access.
	eap_fast_pac_type_e m_pac_type;
#endif //#if defined(USE_FAST_EAP_TYPE)

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H virtual ~tls_extension_c();

	/**
	 * Constructor initializes object.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H tls_extension_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * Function copies the object.
	 */
	tls_extension_c * copy() const;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H bool get_is_valid();

	/**
	 * This function sets the extension lifitime hint.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H void set_lifetime_hint(const u32_t lifetime_hint);

	/**
	 * This function gets the extension lifetime hint.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H u32_t get_lifetime_hint() const;

	/**
	 * This function sets the extension type.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H void set_type(const tls_extension_type_e type);

	/**
	 * This function gets the extension type.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H tls_extension_type_e get_type() const;

#if defined(USE_FAST_EAP_TYPE)

	/// This function stores the PAC-Type for fast access.
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H void set_pac_type(const eap_fast_pac_type_e pac_type);

	/// This function returns the PAC-Type for fast access.
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H eap_fast_pac_type_e get_pac_type() const;

#endif //#if defined(USE_FAST_EAP_TYPE)

	/**
	 * This function gets the debug string of the extension type.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H static eap_const_string  get_type_string(tls_extension_type_e type);

	/**
	 * This function gets the extension from the array of extensions.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H static const tls_extension_c * get_tls_extension(
		const tls_extension_type_e tls_extension_type,
		EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
		abs_eap_am_tools_c * const am_tools);

#if defined(USE_FAST_EAP_TYPE)
	/**
	 * This function gets the extension from the array of extensions.
	 */
	EAP_FUNC_VISIBILITY_TLS_EXTENSION_H static const tls_extension_c * get_tls_extension(
		const tls_extension_type_e tls_extension_type,
		const eap_fast_pac_type_e pac_type,
		EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
		abs_eap_am_tools_c * const am_tools);
#endif //#if defined(USE_FAST_EAP_TYPE)

	// 
	//--------------------------------------------------
}; // class tls_extension_c


//--------------------------------------------------

#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

#endif //#if !defined(_TLS_EXTENSION_H_)

// End.
