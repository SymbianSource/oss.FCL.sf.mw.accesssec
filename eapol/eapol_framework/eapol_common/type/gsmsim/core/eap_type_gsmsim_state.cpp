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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 83 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_type_gsmsim_header.h"
#include "eap_type_gsmsim_types.h"
#include "eap_type_gsmsim_payloads.h"
#include "abs_eap_type_gsmsim_state.h"
#include "abs_eap_base_timer.h"
#include "eap_type_gsmsim_state.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"

//--------------------------------------------------


EAP_FUNC_EXPORT eap_type_gsmsim_state_variable_parameters_c::~eap_type_gsmsim_state_variable_parameters_c()
{
}

EAP_FUNC_EXPORT eap_type_gsmsim_state_variable_parameters_c::eap_type_gsmsim_state_variable_parameters_c()
	: m_must_be_initiator(false)
	, m_must_be_responder(false)
{
	u32_t ind = 0;
	for (ind = 0; ind < GSMSIM_STATE_MAX_TYPES; ind++)
	{
		m_valid_types[ind] = gsmsim_subtype_NONE;
	}
}


EAP_FUNC_EXPORT bool eap_type_gsmsim_state_variable_parameters_c::check_valid_types(gsmsim_subtype_e type) const
{
	for (u32_t ind = 0u; ind < GSMSIM_STATE_MAX_TYPES; ind++)
	{
		if (type == m_valid_types[ind])
		{
			return true;
		}
	}
	return false;
}

EAP_FUNC_EXPORT bool eap_type_gsmsim_state_variable_parameters_c::check_initiator(const bool is_initiator) const
{
	if ((m_must_be_initiator == true && is_initiator == false)
		|| (m_must_be_responder == true && is_initiator == true))
	{
		return false;
	}
	return true;
}

EAP_FUNC_EXPORT void eap_type_gsmsim_state_variable_parameters_c::init_state(
	const bool must_be_initiator,
	const bool must_be_responder,
	const gsmsim_subtype_e type0,
	const gsmsim_subtype_e type1,
	const gsmsim_subtype_e type2,
	const gsmsim_subtype_e type3)
{
	m_must_be_initiator = (must_be_initiator);
	m_must_be_responder = (must_be_responder);
	m_valid_types[0] = (type0);
	m_valid_types[1] = (type1);
	m_valid_types[2] = (type2);
	m_valid_types[3] = (type3);
}


//--------------------------------------------------



// End.
