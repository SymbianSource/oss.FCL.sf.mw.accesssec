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

#if !defined(_ABS_EAP_AM_TYPE_SIM_H_)
#define _ABS_EAP_AM_TYPE_SIM_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_TYPE_SIM_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIM_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIM_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_TYPE_SIM_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIM_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIM_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIM_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_sim_triplets.h"

// 
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIM_H abs_eap_am_type_sim_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eap_am_type_sim_c()
	{
	}

	// 
	abs_eap_am_type_sim_c()
	{
	}

	virtual eap_status_e complete_SIM_triplets(
		eap_type_sim_triplet_array_c * const triplets) = 0;

	virtual eap_status_e complete_SIM_kc_sres(
		const eap_variable_data_c * const n_rand,
		const eap_variable_data_c * const n_kc,
		const eap_variable_data_c * const n_sres) = 0;


	//--------------------------------------------------
}; // class abs_eap_am_type_sim_c

#endif //#if !defined(_ABS_EAP_AM_TYPE_SIM_H_)

//--------------------------------------------------



// End.
