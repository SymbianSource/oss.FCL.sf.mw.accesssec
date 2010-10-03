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

#if !defined(_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H_)
#define _EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H_

//#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H 
#elif defined(EAP_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_variable_data.h"

//-----------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_type_aka_authentication_vector_c
{
private:

	abs_eap_am_tools_c * m_am_tools;

	eap_variable_data_c m_RAND;
	eap_variable_data_c m_AUTN;
	eap_variable_data_c m_RES;
	eap_variable_data_c m_CK;
	eap_variable_data_c m_IK;
	eap_variable_data_c m_AUTS;

	eap_status_e m_vector_status;

	bool m_is_valid;

public:

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H virtual ~eap_type_aka_authentication_vector_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_type_aka_authentication_vector_c(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_variable_data_c * get_RAND() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_variable_data_c * get_AUTN() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_variable_data_c * get_RES() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_variable_data_c * get_CK() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_variable_data_c * get_IK() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_variable_data_c * get_AUTS() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_type_aka_authentication_vector_c * copy() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H void reset();

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H void set_vector_status(eap_status_e vector_status);

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H eap_status_e get_vector_status() const;

	EAP_FUNC_VISIBILITY_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H bool get_is_valid() const;
};


#endif //#if !defined(_EAP_TYPE_AKA_AUTHENTICATION_VECTOR_H_)

//--------------------------------------------------



// End.
