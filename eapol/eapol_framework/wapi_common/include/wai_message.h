/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wai_message.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 10 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_WAI_MESSAGE_H_)
#define _WAI_MESSAGE_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "eap_array.h"

/** @file */


//----------------------------------------------------------------------------


/// This class defines one WAI-message. One WAI message could include many WAI TLV attributes.
/**
 * This class defined one WAI-message.
 * Parse and analyse of WAI-message is asyncronous.
 * m_analyse_index tells the index of message where asyncronous
 * analyse of WAI-message must continue.
 * Analysed messages are skipped during the asyncronous
 * analyse of messages. Asyncronous analyse is needed
 * because of the PKI functions are asyncronous in
 * Symbian.
 */
class EAP_EXPORT wai_message_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This buffer includes copy of the whole received WAI-message data.
	eap_variable_data_c m_message_data;

	/// This indicates whether this object is client (true) or server (false). This is mostly for traces.
	const bool m_is_client;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the wai_message_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~wai_message_c();

	/**
	 * The constructor of the wai_message_c class simply initializes the attributes.
	 */
	EAP_FUNC_IMPORT wai_message_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client);

	/**
	 * This function resets this object.
	 */
	EAP_FUNC_IMPORT eap_status_e reset();

	/**
	 * This function copies the received WAI-message data.
	 */
	EAP_FUNC_IMPORT eap_status_e set_wai_message_data(
		const eap_variable_data_c * const wai_message_data);

	/**
	 * This function returns the WAI-message data.
	 */
	EAP_FUNC_IMPORT const eap_variable_data_c * get_wai_message_data() const;

	/**
	 * This function returns the WAI-message data.
	 */
	EAP_FUNC_IMPORT eap_variable_data_c * get_wai_message_data_writable();

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT wai_message_c * copy() const;
	
	//--------------------------------------------------
}; // class wai_message_c


//--------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_WAI_MESSAGE_H_)

// End.
