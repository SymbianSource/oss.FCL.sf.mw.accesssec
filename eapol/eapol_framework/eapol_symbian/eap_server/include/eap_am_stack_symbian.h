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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 27 %
*/

#ifndef EAP_AM_STACK_SYMBIAN_H_
#define EAP_AM_STACK_SYMBIAN_H_

#include "eap_am_stack.h"
#include "abs_eap_am_stack.h"
#include "abs_eap_am_tools.h"
#include "eap_automatic_variable.h"
#include <e32base.h>
#include <e32std.h>
#include <d32dbms.h>
#include "eap_config.h"
#include "eap_file_config.h"
#include "eap_am_file_input_symbian.h"
#include "eap_type_selection.h"
#include "eapol_key_types.h"

#include "eapol_wlan_database_reference.h"
#include <EapTypePlugin.h>
#include "eap_base_type.h"
#include "abs_eap_configuration_if.h"
#include "eap_tlv_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_STACK_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_STACK_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_STACK_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_STACK_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.


class EAP_CLASS_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_am_stack_symbian_c
: public CActive
, public eap_am_stack_c
, public abs_eap_configuration_if_c
{
public:
   
    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_am_stack_symbian_c(class abs_eap_am_tools_c * tools, bool is_client_when_true);
    
    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H virtual ~eap_am_stack_symbian_c();
  
    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H bool get_is_valid();

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e set_partner(
        abs_eap_am_stack_c * const partner
        , abs_eap_configuration_if_c * const configuration_if
        );

    // This is documented in abs_eap_stack_interface_c::configure().
    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

    // This is documented in abs_eap_stack_interface_c::shutdown().
    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e shutdown();

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e read_configure(
        const eap_configuration_field_c * const field,
        eap_variable_data_c * const data);

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e set_timer(
        abs_eap_base_timer_c * const p_initializer, 
        const u32_t p_id, 
        void * const p_data,
        const u32_t p_time_ms);

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e cancel_timer(
        abs_eap_base_timer_c * const p_initializer, 
        const u32_t p_id);

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e check_is_valid_eap_type(
        const eap_type_value_e eap_type);

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e get_eap_type_list(
        eap_array_c<eap_type_value_e> * const eap_type_list);

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e load_module(
        const eap_type_value_e type,
        const eap_type_value_e tunneling_type,
        abs_eap_base_type_c * const partner,
        eap_base_type_c ** const eap_type,
        const bool is_client_when_true,
        const eap_am_network_id_c * const receive_network_id);

    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e save_simple_config_session(
        const simple_config_state_e state,
        EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
        const eap_variable_data_c * const new_password,
        const simple_config_Device_Password_ID_e Device_Password_ID,
        const simple_config_payloads_c * const other_configuration);
    
    EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e set_eap_database_reference_values(
            const eap_variable_data_c * const reference);

	EAP_FUNC_VISIBILITY_EAP_AM_STACK_SYMBIAN_H eap_status_e get_802_11_authentication_mode(
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_authentication_type_e authentication_type);

private:
    
    /// Function reads one configuration value from database.
    void read_configureL(
        const TDesC& aDbName,
        const TDesC& aTableName,
        eap_config_string field,
        const u32_t /*field_length*/,
        eap_variable_data_c * const data);

    /// Control function of this active-object.
    void RunL();

    /// Cancel function for active-object.
    void DoCancel();

    /// RunError function for active-object.
	TInt RunError(TInt aError);


	void SetToTopPriorityL(const eap_type_value_e aEapType);

	eap_status_e reset_eap_configuration();

	void ReadEAPSettingsL();

	eap_status_e reset_eap_plugins();

	TInt get_current_eap_index();

	void set_current_eap_index(const TInt ind);

    
    abs_eap_am_tools_c * const iTools;

    TBool iIsValid;

    const TBool iIsClient;

    abs_eap_am_stack_c* iPartner;

    /// Handle of database session.
    RDbs iSession;

    /// Handle of database file.
    RFs iFs;
    
	eap_file_config_c m_client_config;

    eap_file_config_c * iFileconfig;
    
    RPointerArray<CEapTypePlugin> m_plugin_if_array;


	eap_array_c<eap_type_value_e> iEnabledEapMethodsArray;
	eap_array_c<eap_type_value_e> iDisabledEapMethodsArray;


    /// Array which corresponds with m_plugin_if_array and indicates the types of the loaded EAP types. 
    eap_array_c<eap_type_value_e> m_eap_type_array;

	abs_eap_configuration_if_c* iConfigurationIf;

	TIndexType iIndexType;

	TUint iIndex;

	TInt iCurrentEapIndex;

	/// WLAN authentication type.
	eapol_key_authentication_type_e m_selected_eapol_key_authentication_type;
};

#endif /* EAP_AM_STACK_SYMBIAN_H_ */

// end
