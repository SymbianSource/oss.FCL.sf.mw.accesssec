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

#if !defined(_EAP_AM_TYPE_SIM_H_)
#define _EAP_AM_TYPE_SIM_H_

#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_SIM_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIM_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIM_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_SIM_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIM_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIM_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIM_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_type_sim.h"
#include "eap_sim_triplets.h"

// 
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_H eap_am_type_sim_c
{
private:
	//--------------------------------------------------

	abs_eap_am_type_sim_c *m_am_partner;
	abs_eap_am_tools_c *m_am_tools;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_am_type_sim_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	// 
	eap_am_type_sim_c(abs_eap_am_tools_c * const tools, abs_eap_am_type_sim_c * const partner)
	: m_am_partner(partner)
	, m_am_tools(tools)
	, m_is_valid(false)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		set_is_valid();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	// 
	abs_eap_am_type_sim_c * const get_am_partner()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return m_am_partner;
	}

	void set_is_valid()
	{
		m_is_valid = true;
	}

	bool get_is_valid()
	{
		return m_is_valid;
	}

	//
	virtual eap_status_e query_SIM_imsi(
		u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length) = 0;

	//
	virtual eap_status_e query_SIM_kc_and_sres(
		const u8_t * const imsi, const u32_t imsi_length,
		const u8_t * const rand, const u32_t rand_length,
		u8_t * const kc, u32_t * const kc_length,
		u8_t * const sres, u32_t * const sres_length) = 0;

	//
	virtual eap_status_e query_SIM_triplets(
		const eap_variable_data_c * const imsi,
		eap_type_sim_triplet_array_c * const triplets) = 0;

	//
	virtual eap_status_e query_SIM_kc_sres(
		const eap_variable_data_c * const n_rands,
		eap_variable_data_c * const n_kc,
		eap_variable_data_c * const n_sres) = 0;

	//--------------------------------------------------
}; // class eap_am_type_sim_c

#endif //#if !defined(_EAP_AM_TYPE_SIM_H_)

//--------------------------------------------------



// End.
