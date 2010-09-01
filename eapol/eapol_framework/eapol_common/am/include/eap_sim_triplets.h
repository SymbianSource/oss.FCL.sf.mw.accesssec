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
* %version: 4 %
*/

#if !defined(_EAP_SIM_TRIPLETS_H_)
#define _EAP_SIM_TRIPLETS_H_

//#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_variable_data.h"


//-----------------------------------------------

const u32_t SIM_RAND_LENGTH = 16u;
const u32_t SIM_KC_LENGTH   = 8u;
const u32_t SIM_SRES_LENGTH = 4u;


class EAP_EXPORT eap_type_saesim_triplet_c
{
private:

	eap_variable_data_c *m_kc;
	eap_variable_data_c *m_rand;
	eap_variable_data_c *m_sres;
	bool m_is_valid;

public:

	EAP_FUNC_IMPORT virtual ~eap_type_saesim_triplet_c();

	EAP_FUNC_IMPORT eap_type_saesim_triplet_c(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_IMPORT void reset();

	EAP_FUNC_IMPORT eap_status_e set_triplet(
		eap_variable_data_c * const kc,
		eap_variable_data_c * const rand,
		eap_variable_data_c * const sres
		);

	EAP_FUNC_IMPORT eap_type_saesim_triplet_c * copy(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_IMPORT void set_is_valid();

	EAP_FUNC_IMPORT bool get_is_valid();

	EAP_FUNC_IMPORT eap_variable_data_c *get_kc();

	EAP_FUNC_IMPORT eap_variable_data_c *get_rand();

	EAP_FUNC_IMPORT eap_variable_data_c *get_sres();
};

//-----------------------------------------------

class EAP_EXPORT eap_type_sim_triplet_array_c
{
private:

	u32_t m_triplet_count;
	eap_type_saesim_triplet_c **m_array;
	abs_eap_am_tools_c * m_am_tools;

public:

	EAP_FUNC_IMPORT virtual ~eap_type_sim_triplet_array_c();

	EAP_FUNC_IMPORT eap_type_sim_triplet_array_c(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_IMPORT eap_status_e set_triplet_count(
		const u32_t triplet_count
		);

	EAP_FUNC_IMPORT eap_type_saesim_triplet_c * add_triplet();

	EAP_FUNC_IMPORT eap_type_saesim_triplet_c * get_triplet(abs_eap_am_tools_c * const m_am_tools, u32_t index);

	EAP_FUNC_IMPORT eap_status_e set_triplet(u32_t index, eap_type_saesim_triplet_c * const triplet);

	EAP_FUNC_IMPORT u32_t get_triplet_count();

	EAP_FUNC_IMPORT eap_type_sim_triplet_array_c * copy();

	EAP_FUNC_IMPORT void reset();

};


#endif //#if !defined(_EAP_SIM_TRIPLETS_H_)

//--------------------------------------------------



// End.
