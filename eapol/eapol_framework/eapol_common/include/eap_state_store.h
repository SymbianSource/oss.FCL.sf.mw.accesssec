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

#if !defined(_EAP_STATE_STORE_H_)
#define _EAP_STATE_STORE_H_

#error Do not use.

#include "eap_am_memory.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_STATE_STORE_H)
	#define EAP_CLASS_VISIBILITY_EAP_STATE_STORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_STATE_STORE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_STATE_STORE_H 
	#define EAP_FUNC_EXPORT_EAP_STATE_STORE_H 
	#define EAP_C_FUNC_EXPORT_EAP_STATE_STORE_H 
#elif defined(EAP_EXPORT_EAP_STATE_STORE_H)
	#define EAP_CLASS_VISIBILITY_EAP_STATE_STORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_STATE_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_STATE_STORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_STATE_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_STATE_STORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_STATE_STORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_STATE_STORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_STATE_STORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_STATE_STORE_H 
	#define EAP_C_FUNC_EXPORT_EAP_STATE_STORE_H 
#endif
// End: added by script change_export_macros.sh.


class EAP_CLASS_VISIBILITY_EAP_STATE_STORE_H eap_base_type_state_c
{
private:
	//--------------------------------------------------
	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_base_type_state_c()
	{
	}

	// 
	eap_base_type_state_c()
	{
	}

	//--------------------------------------------------
};


const u32_t EAP_STATE_SIZE = (u32_t)(((~0u) & 0xff)+1u);


class EAP_CLASS_VISIBILITY_EAP_STATE_STORE_H eap_state_store_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_base_type_state_c *m_state[EAP_STATE_SIZE]; // Only 256 different identifier could exist.

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_state_store_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		for (u32_t ind = 0; ind < EAP_STATE_SIZE; ind++)
		{
			delete m_state[ind];
			m_state[ind] = 0;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	// 
	eap_state_store_c(abs_eap_am_tools_c * const tools)
		: m_am_tools(tools)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		for (u32_t ind = 0; ind < EAP_STATE_SIZE; ind++)
		{
			m_state[ind] = 0;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	//
	eap_status_e add(eap_base_type_state_c * const state, const u8_t identifier)
	{
		if (m_state[identifier] == 0)
		{
			m_state[identifier] = state;
			return eap_status_ok;
		}
		else
		{
			EAP_ASSERT_ALWAYS(m_state[identifier] == 0);
		}
		return eap_status_handler_does_not_exists_error;
	}

	//
	eap_base_type_state_c * const get(const u8_t identifier)
	{
		return m_state[identifier];
	}

	//
	eap_status_e remove(const u8_t identifier)
	{
		if (m_state[identifier] != 0)
		{
			delete m_state[identifier];
			m_state[identifier] = 0;
			return eap_status_ok;
		}
		else
		{
			EAP_ASSERT_ALWAYS(m_state[identifier] != 0);
		}
		return eap_status_handler_does_not_exists_error;
	}

	//--------------------------------------------------
};


#endif //#if !defined(_EAP_STATE_STORE_H_)

//--------------------------------------------------



// End.
