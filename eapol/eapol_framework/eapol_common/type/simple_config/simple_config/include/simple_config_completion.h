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

#if !defined(_SIMPLE_CONFIG_COMPLETION_H_)
#define _SIMPLE_CONFIG_COMPLETION_H_

#include "eap_tools.h"
#include "eap_array.h"
//#include "simple_config_record_message.h"
#include "abs_simple_config_message_hash.h"

/** @file */

/**
 * This is enumeration of SIMPLE_CONFIG competion actions.
 */
enum simple_config_completion_action_e
{
	simple_config_completion_action_none,                                               ///< Initialization value means no action.
	simple_config_completion_action_process_simple_config_attributes,                      ///< process_simple_config_attributes
};

//----------------------------------------------------------------------------


/// This class defines one SIMPLE_CONFIG completion action.
class EAP_EXPORT simple_config_completion_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This variable stores the completion action.
	simple_config_completion_action_e m_completion_action;

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
	EAP_FUNC_IMPORT virtual ~simple_config_completion_c();

	/**
	 * Constructor initializes object.
	 */
	EAP_FUNC_IMPORT simple_config_completion_c(
		abs_eap_am_tools_c * const tools,
		simple_config_completion_action_e completion_action);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_IMPORT bool get_is_valid();

	/**
	 * This function sets the completion action type.
	 */
	EAP_FUNC_IMPORT void set_completion_action(simple_config_completion_action_e completion_action);

	/**
	 * This function gets the completion action type.
	 */
	EAP_FUNC_IMPORT simple_config_completion_action_e get_completion_action() const;

	/**
	 * This function gets the debug string of the completion action type.
	 */
	EAP_FUNC_IMPORT eap_const_string  get_completion_action_string() const;

	// 
	//--------------------------------------------------
}; // class simple_config_completion_c


//--------------------------------------------------

#endif //#if !defined(_SIMPLE_CONFIG_COMPLETION_H_)



// End.
