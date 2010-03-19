/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_completion.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 14 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_EC_CS_COMPLETION_H_)
#define _EC_CS_COMPLETION_H_

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_array_algorithms.h"
#include "ec_cs_tlv_header.h"
#include "ec_cs_types.h"


/** @file */

//----------------------------------------------------------------------------

/**
 * This is enumeration of EC certificate store competion actions.
 */
enum ec_cs_completion_e
{
	ec_cs_completion_none,                           ///< Initialization value means no action.
	ec_cs_completion_internal_select_certificate,
	ec_cs_completion_internal_select_certificate_with_identity,
	ec_cs_completion_internal_complete_add_imported_certificate_file,
	ec_cs_completion_complete_add_imported_certificate_file,
	ec_cs_completion_query_PAC_store_password,
	ec_cs_completion_add_imported_ca_certificate,
	ec_cs_completion_add_imported_client_certificate,
	ec_cs_completion_internal_create_signature_with_private_key,
	ec_cs_completion_complete_query_certificate_list,
	ec_cs_completion_internal_verify_signature_with_public_key,
};

//----------------------------------------------------------------------------


/// This class defines one EC certificate store completion action.
class EAP_EXPORT ec_cs_completion_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This variable stores the completion action.
	ec_cs_completion_e m_completion_action;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_IMPORT void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~ec_cs_completion_c();

	/**
	 * Constructor initializes object.
	 */
	EAP_FUNC_IMPORT ec_cs_completion_c(
		abs_eap_am_tools_c * const tools,
		ec_cs_completion_e completion_action);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_IMPORT bool get_is_valid();

	/**
	 * This function sets the completion action type.
	 */
	EAP_FUNC_IMPORT void set_completion_action(ec_cs_completion_e completion_action);

	/**
	 * This function gets the completion action type.
	 */
	EAP_FUNC_IMPORT ec_cs_completion_e get_completion_action() const;

	/**
	 * This function gets the debug string of the completion action type.
	 */
	EAP_FUNC_IMPORT static eap_const_string get_completion_action_string(ec_cs_completion_e completion_action);

	// 
	//--------------------------------------------------
}; // class ec_cs_completion_c


//----------------------------------------------------------------------------

#endif //#if !defined(_EC_CS_COMPLETION_H_)


// End.
