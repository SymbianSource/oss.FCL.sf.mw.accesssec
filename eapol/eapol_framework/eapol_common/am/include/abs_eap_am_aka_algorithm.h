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

#if !defined(_ABS_AKA_ALGORITHM_H_)
#define _ABS_AKA_ALGORITHM_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "abs_eap_am_tools.h"
#include "eap_am_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_AKA_ALGORITHM_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_type_aka_authentication_vector.h"

enum aka_algorithm_e
{
	aka_algorithm_none,
	aka_algorithm_nokia_test_network_xor,
	aka_algorithm_tls_prf_with_shared_secret,
	aka_algorithm_milenage,
};


/// This class is implements Nokia test network AKA algorithm.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_AKA_ALGORITHM_H abs_eap_am_aka_algorithm_c
{
private:
	//--------------------------------------------------

	virtual void set_is_valid() = 0;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eap_am_aka_algorithm_c(){};

	virtual eap_status_e shutdown() = 0;


	virtual bool get_is_valid() = 0;


	virtual eap_status_e set_simulator_aka_k(
		const eap_variable_data_c * const simulator_aka_ki) = 0;

	virtual eap_status_e set_simulator_aka_op(
		const eap_variable_data_c * const simulator_aka_op) = 0;

	virtual eap_status_e set_simulator_aka_amf(
		const eap_variable_data_c * const simulator_aka_amf) = 0;

	virtual eap_status_e set_do_ramdom_synchronization_error() = 0;


	virtual eap_status_e generate_authentication_vector(
		eap_type_aka_authentication_vector_c * const authentication_vector) = 0;

	virtual eap_status_e generate_RES(
		eap_type_aka_authentication_vector_c * const authentication_vector) = 0;

	virtual eap_status_e re_synchronize(
		eap_type_aka_authentication_vector_c * const authentication_vector) = 0;

	//--------------------------------------------------
}; // class abs_eap_am_aka_algorithm_c


/** @file */ 

#endif //#if !defined(_ABS_AKA_ALGORITHM_H_)

//--------------------------------------------------



// End.
