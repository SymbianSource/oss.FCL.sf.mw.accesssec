/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  This class defines Credential attributes for protected setup (previously known as simple config).
*
*/

/*
* %version: 9 %
*/

#if !defined(_SIMPLE_CONFIG_CREDENTIAL_H_)
#define _SIMPLE_CONFIG_CREDENTIAL_H_

#include "eap_tools.h"
#include "simple_config_attribute_type.h"
#include "simple_config_types.h"
#include "eap_array_algorithms.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H 
#elif defined(EAP_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_CREDENTIAL_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


//----------------------------------------------------------------------------


/// This class defines Credential attributes for protected setup (previously known as simple config).
class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H simple_config_credential_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	u8_t m_network_index;

	eap_variable_data_c m_SSID;

	simple_config_Authentication_Type_e m_Authentication_Type;

	simple_config_Encryption_Type_e m_Encryption_Type;

	eap_array_c<network_key_and_index_c> m_network_keys;

	eap_variable_data_c m_MAC_address;

	bool m_is_valid;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the simple_config_credential_c class does nothing.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H virtual ~simple_config_credential_c();

	/**
	 * The constructor of the simple_config_credential_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H simple_config_credential_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H void set_network_index(const u8_t index);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H u8_t get_network_index() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H eap_variable_data_c * get_SSID();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H const eap_variable_data_c * get_SSID_const() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H simple_config_Authentication_Type_e get_Authentication_Type();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H void set_Authentication_Type(const simple_config_Authentication_Type_e Authentication_Type);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H simple_config_Encryption_Type_e get_Encryption_Type();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H void set_Encryption_Type(const simple_config_Encryption_Type_e Encryption_Type);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H eap_array_c<network_key_and_index_c> * get_network_keys();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H const eap_array_c<network_key_and_index_c> * get_network_keys_const() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H eap_variable_data_c * get_MAC_address();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H const eap_variable_data_c * get_MAC_address_const() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_CREDENTIAL_H bool get_is_valid();

	// 
	//--------------------------------------------------
}; // class simple_config_credential_c


//--------------------------------------------------

#endif //#if !defined(_SIMPLE_CONFIG_CREDENTIAL_H_)



// End.
