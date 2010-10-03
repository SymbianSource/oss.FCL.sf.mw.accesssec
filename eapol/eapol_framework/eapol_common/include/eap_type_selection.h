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

#if !defined(_EAP_TYPE_SELECTION_H_)
#define _EAP_TYPE_SELECTION_H_

#include "eap_am_assert.h"
#include "eap_variable_data.h"
#include "eap_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_SELECTION_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SELECTION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SELECTION_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SELECTION_H 
#elif defined(EAP_EXPORT_EAP_TYPE_SELECTION_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SELECTION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SELECTION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SELECTION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SELECTION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SELECTION_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SELECTION_H 
#endif
// End: added by script change_export_macros.sh.


//--------------------------------------------------

class abs_eap_am_tools_c;


/// eap_type_selection_c class stores infofmation of one supported EAP-type.
class EAP_CLASS_VISIBILITY_EAP_TYPE_SELECTION_H eap_type_selection_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	const eap_type_value_e m_type;

	const bool m_is_enabled;

	bool m_is_valid;

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_type_selection_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H virtual ~eap_type_selection_c();

	/**
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H eap_type_selection_c(
		abs_eap_am_tools_c * const tools,
		const eap_type_value_e type,
		const bool is_enabled);

	/**
	 * The get_type() function returns EAP-type.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H eap_type_value_e get_type() const;

	/**
	 * The get_is_enabled() function returns true when EAP-type is enabled.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H bool get_is_enabled() const;

	/**
	 * The copy() function copies the eap_type_selection_c object and data.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H eap_type_selection_c * copy() const;

	/**
	 * The get_is_valid() function returns the status of the object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H bool get_is_valid() const;

	/**
	 * The get_is_valid_data() function returns the status of the
	 * data included in eap_type_selection_c object.
	 * @return True indicates the object includes valid data.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_SELECTION_H bool get_is_valid_data() const;

}; // class eap_type_selection_c


#endif //#if !defined(_EAP_TYPE_SELECTION_H_)

//--------------------------------------------------


// End.
