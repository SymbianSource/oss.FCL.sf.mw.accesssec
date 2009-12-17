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




#if !defined(_ABS_EAP_AM_TYPE_SIM_H_)
#define _ABS_EAP_AM_TYPE_SIM_H_

#include "eap_am_export.h"
#include "eap_sim_triplets.h"

// 
class EAP_EXPORT abs_eap_am_type_sim_c
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
