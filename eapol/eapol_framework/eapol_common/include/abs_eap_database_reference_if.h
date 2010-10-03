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

#if !defined(_ABS_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_)
#define _ABS_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_

//--------------------------------------------------

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H 
#elif defined(EAP_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_DATABASE_REFERENCE_IF_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_types.h"
#include "eap_status.h"


/// This class is abstract interface to reference of WLAN database of the current connection.
class EAP_CLASS_VISIBILITY_ABS_EAP_DATABASE_REFERENCE_IF_H abs_eap_database_reference_if_c_deprecated
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~abs_eap_database_reference_if_c_deprecated()
	{
	}

	/**
	 * The constructor of the abs_eap_database_reference_if_c class does nothing special.
	 */
	virtual eap_status_e get_wlan_database_reference_values(
		eap_variable_data_c * const reference) const = 0;

}; // class abs_eap_database_reference_if_c


#endif //#if !defined(_ABS_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_)

//--------------------------------------------------


// End.
