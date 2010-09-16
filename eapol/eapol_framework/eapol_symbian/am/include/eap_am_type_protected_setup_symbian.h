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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 13.1.12 %
*/

#if !defined(_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H_)
#define _EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H_


//  INCLUDES

#include <EapType.h>
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_base_type.h"

#include "abs_eap_am_type_simple_config.h"
#include "eap_am_type_simple_config.h"

#include <ssl.h>
#include "simple_config_payloads.h"
#include "eapol_key_types.h"
#include "eapol_rsna_key_header.h"
#include "eap_config.h"
#include "eap_variable_data.h"

#include "EapProtectedSetupInterface.h"
#include <etelmm.h>

// FORWARD DECLARATIONS
class abs_eap_configuration_if_c;

// CLASS DECLARATION

/**
* Class that implements the operating system dependent portion of 
* EAP Protected setup protocol for Symbian OS.
*/


class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H CEapAmProtectedSetupSymbian
: public CBase
, public eap_am_type_simple_config_c
{
public:

	//--------------------------------------------------	
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H static CEapAmProtectedSetupSymbian* NewL(
		abs_eap_am_tools_c * const tools,
		abs_eap_base_type_c * const partner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id,
		abs_eap_configuration_if_c * const configuration_if);
		
	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H virtual ~CEapAmProtectedSetupSymbian();	
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H void set_is_valid();	
		
	/**  From the parent eap_am_type_simple_config_c **/

	/** Function sets partner object of adaptation module of EAP-SIMPLE_CONFIG.
	 *  Partner object is the EAP-SIMPLE_CONFIG object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H void set_am_partner(abs_eap_am_type_simple_config_c * const partner);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e configure();

	/**
	 * The shutdown() function is called before the destructor of the 
	 * object is executed. During the function call the object 
	 * could shutdown the operations, for example cancel timers.
	 * Each derived class must define this function.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e shutdown();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H bool get_is_valid();

	/** Client calls this function.
	 *  EAP-SIMPLE_CONFIG AM could do finishing operations to databases etc. based on authentication status and type.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e reset();

	/** Client calls this function.
	 *  EAP-SIMPLE_CONFIG AM could make some fast operations here, heavy operations should be done in the reset() function.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e authentication_finished(
		const bool true_when_successfull,
		const bool true_when_session_resumed);

	/** Client calls this function.
	 *  AM must copy identity to output parameters if call is syncronous.
	 *  This function could be completed asyncronously with abs_eap_am_type_simple_config_c::complete_query_eap_identity_query() function call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e query_eap_identity(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		bool * const use_manual_username,
		eap_variable_data_c * const manual_username,
		bool *const use_manual_realm,
		eap_variable_data_c * const manual_realm
		);

	/** 
	 * Cancels the outstanding indentity query.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e cancel_identity_query();

	/**
	 * The type_configure_read() function reads the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the query to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The type_configure_write() function writes the configuration data identified
	 * by the field string of field_length bytes length. Adaptation module must direct
	 * the action to some persistent store.
	 * @param field is generic configure string idenfying the required configure data.
	 * @param field_length is length of the field string.
	 * @param data is pointer to existing eap_variable_data object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	/**
	 * The load_module() function function indicates the lower level to
	 * load new module of EAP-type.
	 * @param type is the requested EAP-type.
	 * @param partner is pointer to the caller object.
	 * The partner of the new created EAP-type object is the caller object.
	 * @param eap_type is a pointer to a pointer of EAP-type object.
	 * Adaptation module sets eap_type pointer to created EAP-type object.
	 * @param is_client_when_true parameter indicates whether the network entity should
	 * act as a client (true) or server (false), in terms of EAP-protocol whether
	 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e load_module(
		const eap_type_value_e type,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id);

	/**
	 * This is needed by PEAP type.
	 * This function queries the validity of EAP-type.
	 * Lower layer should return eap_status_ok if this EAP-type is supported.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e check_is_valid_eap_type(const eap_type_value_e eap_type);

	/**
	 * This function queries the list of supported EAP-types.
	 * Lower layer should return eap_status_ok if this call succeeds.
	 * @param eap_type_list will include the list of supported EAP-types. Each value in list
	 * is type of u32_t and represent one supported EAP-type. List consists of subsequent u32_t type values.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e get_eap_type_list(
		eap_array_c<eap_type_value_e> * const eap_type_list);

	/**
	 * This is needed by PEAP type.
	 * The unload_module() function unloads the module of a EAP-type. 
	 * @param type is the requested EAP-type.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e unload_module(const eap_type_value_e type);
	
	
	/**  From simple_config_am_services_c through the parent eap_am_type_simple_config_c **/

	/// This function sets pointer to adaptation module of SIMPLE_CONFIG. See abs_simple_config_am_services_c.	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H void set_simple_config_am_partner(abs_simple_config_am_services_c * const simple_config_am_partner);
	
	/**
	 * This function queries all network and device parameters.
	 * abs_simple_config_am_services_c::complete_query_network_and_device_parameters() completes this query.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e query_network_and_device_parameters(
		const simple_config_state_e state);

	/**
	 * This function tells AM to save SIMPLE_CONFIG configuration parameters.
	 * This is always syncronous call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration
		);

	/**
	 * This function forwards all payloads received in M2D messages.
	 * Adaptation layer could show this information to user.
	 * This is always syncronous call.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e received_registrar_information(
		EAP_TEMPLATE_CONST eap_array_c<simple_config_payloads_c> * const M2D_payloads);

	/**
	 * This function cancels query_network_and_device_parameters() query.
	 * After this call AM MUST NOT complete related query.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e cancel_query_network_and_device_parameters();


	/** Own Public functions **/
	
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H eap_status_e complete_protected_setup_device_paramsL(
		const RMobilePhone::TMobilePhoneIdentityV1 &phone_identity,
		const eap_status_e completion_status);
			
	//--------------------------------------------------
	
protected:

	//--------------------------------------------------

	CEapAmProtectedSetupSymbian(
		abs_eap_am_tools_c * const tools,
		abs_eap_base_type_c * const partner,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e eap_type,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id,
		abs_eap_configuration_if_c * const configuration_if);

	void ConstructL();

	//--------------------------------------------------

private:

	abs_simple_config_am_services_c * get_simple_config_am_partner();

	abs_eap_am_type_simple_config_c * get_am_partner();

	void send_error_notification(const eap_status_e error);

	eap_status_e read_memory_store(
		const eap_type_protected_setup_stored_e data_type,
		eap_variable_data_c * const data);

	void ConvertUnicodeToAsciiL(const TDesC16& aFromUnicode, TDes8& aToAscii);

	//--------------------------------------------------

private:

	//--------------------------------------------------

	abs_eap_base_type_c *m_partner;

	TInt m_index;
	
	abs_eap_am_tools_c *m_am_tools;

	abs_eap_am_type_simple_config_c *m_am_partner;

	abs_simple_config_am_services_c * m_simple_config_am_partner;

	abs_eap_configuration_if_c * const m_configuration_if;

	bool m_device_parameters_valid;
	simple_config_payloads_c m_network_and_device_parameters;

	eap_variable_data_c m_UUID_E;

	simple_config_Device_Password_ID_e m_Device_Password_ID;

	eap_am_network_id_c m_receive_network_id;

	u8_t m_eap_identifier;

	eap_type_value_e m_eap_type;

	simple_config_state_e m_simple_config_state;

	bool m_is_valid;
	bool m_is_client;

	bool m_shutdown_was_called;

	eap_variable_data_c m_manual_username;

	eap_variable_data_c m_manual_realm;

	/// This flag allows use of manually configured username in EAP-Identity/Response.
	bool m_use_manual_username;

	/// This flag allows use of manually configured realm in EAP-Identity/Response.
	bool m_use_manual_realm;

	/// This flag prevents double configuration. This can happen when 
	/// this class implements many interfaces.
	bool m_configured;

	// This is the connection to the MMETEL interface from here.
	CEapProtectedSetupInterface* m_prot_setup_if;	
    
	//-----------------------------------------------------------------	
	
}; // class CEapAmProtectedSetupSymbian


#endif //#if !defined(_EAP_AM_TYPE_PROTECTED_SETUP_SYMBIAN_H_)

//--------------------------------------------------

// End of file.
