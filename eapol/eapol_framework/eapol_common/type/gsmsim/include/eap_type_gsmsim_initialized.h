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




#if !defined(_GSMSIM_INITIALIZED_H_)
#define _GSMSIM_INITIALIZED_H_

#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_type_gsmsim_header.h"
#include "eap_type_gsmsim_types.h"
#include "eap_type_gsmsim_payloads.h"
#include "abs_eap_type_gsmsim_state.h"
#include "abs_eap_am_tools.h"


const u32_t GSMSIM_MAX_OFFER_COUNT = 3;


class EAP_EXPORT eap_type_gsmsim_initialized_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_counter;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_type_gsmsim_initialized_c();

	// 
	eap_type_gsmsim_initialized_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_type_gsmsim_state_c * const /*partner*/);

	u32_t counter();

	void increment();

	void reset();

};


#endif //#if !defined(_GSMSIM_INITIALIZED_H_)

//--------------------------------------------------



// End.
