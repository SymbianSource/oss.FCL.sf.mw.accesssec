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
	#define EAP_FILE_NUMBER_ENUM 36 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_sim_triplets.h"
#include "abs_eap_am_tools.h"


EAP_FUNC_EXPORT eap_type_saesim_triplet_c::~eap_type_saesim_triplet_c()
{
	reset();
}

EAP_FUNC_EXPORT eap_type_saesim_triplet_c::eap_type_saesim_triplet_c(
	abs_eap_am_tools_c * const tools
	)
	: m_kc(0)
	, m_rand(0)
	, m_sres(0)
	, m_is_valid(false)
{
	m_kc = new eap_variable_data_c(tools);
	m_rand = new eap_variable_data_c(tools);
	m_sres = new eap_variable_data_c(tools);

	if (m_kc == 0
		|| m_rand == 0
		|| m_sres == 0)
	{
		reset();
	}
	else
	{
		eap_status_e status = m_kc->init(SIM_KC_LENGTH);
		if (status != eap_status_ok)
		{
			return;
		}
		m_kc->set_is_valid();

		status = m_rand->init(SIM_RAND_LENGTH);
		if (status != eap_status_ok)
		{
			return;
		}
		m_rand->set_is_valid();

		status = m_sres->init(SIM_SRES_LENGTH);
		if (status != eap_status_ok)
		{
			return;
		}
		m_sres->set_is_valid();

		set_is_valid();
	}
}

EAP_FUNC_EXPORT void eap_type_saesim_triplet_c::reset()
{
	if (m_kc)
	{
		delete m_kc;
		m_kc = 0;
	}
	if (m_rand)
	{
		delete m_rand;
		m_rand = 0;
	}
	if (m_sres)
	{
		delete m_sres;
		m_sres = 0;
	}
}

EAP_FUNC_EXPORT eap_status_e eap_type_saesim_triplet_c::set_triplet(
	eap_variable_data_c * const kc,
	eap_variable_data_c * const rand,
	eap_variable_data_c * const sres
	)
{
	reset();

	m_kc = kc;
	m_rand = rand;
	m_sres = sres;

	if (m_kc == 0
		|| m_rand == 0
		|| m_sres == 0)
	{
		return eap_status_allocation_error;
	}
	return eap_status_ok;
}

EAP_FUNC_EXPORT eap_type_saesim_triplet_c * eap_type_saesim_triplet_c::copy(
	abs_eap_am_tools_c * const tools
	)
{
	eap_type_saesim_triplet_c * const triplet = new eap_type_saesim_triplet_c(tools);

	if (triplet != 0
		&& triplet->get_is_valid() == true)
	{
		eap_status_e status = triplet->set_triplet(
			get_kc()->copy(),
			get_rand()->copy(),
			get_sres()->copy());
		if (status != eap_status_ok)
		{
			delete triplet;
			return 0;
		}
	}
	else
	{
		delete triplet;
		return 0;
	}

	return triplet;
}

EAP_FUNC_EXPORT void eap_type_saesim_triplet_c::set_is_valid()
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool eap_type_saesim_triplet_c::get_is_valid()
{
	return m_is_valid;
}

EAP_FUNC_EXPORT eap_variable_data_c *eap_type_saesim_triplet_c::get_kc()
{
	return m_kc;
}

EAP_FUNC_EXPORT eap_variable_data_c *eap_type_saesim_triplet_c::get_rand()
{
	return m_rand;
}

EAP_FUNC_EXPORT eap_variable_data_c *eap_type_saesim_triplet_c::get_sres()
{
	return m_sres;
}



EAP_FUNC_EXPORT eap_type_sim_triplet_array_c::~eap_type_sim_triplet_array_c()
{
	reset();
}

EAP_FUNC_EXPORT eap_type_sim_triplet_array_c::eap_type_sim_triplet_array_c(
	abs_eap_am_tools_c * const tools
	)
	: m_triplet_count(0)
	, m_array(0)
	, m_am_tools(tools)
{
}

EAP_FUNC_EXPORT eap_status_e eap_type_sim_triplet_array_c::set_triplet_count(
	const u32_t triplet_count
	)
{
	m_triplet_count = triplet_count;

	m_array = new eap_type_saesim_triplet_c *[m_triplet_count];

	if (m_array != 0)
	{
		u32_t ind = 0;

		for (ind = 0; ind < m_triplet_count; ind++)
		{
			m_array[ind] = 0;
		}

		for (ind = 0; ind < m_triplet_count; ind++)
		{
			m_array[ind] = new eap_type_saesim_triplet_c(m_am_tools);
			if (m_array[ind] == 0)
			{
				return eap_status_allocation_error;
			}
		}
		return eap_status_ok;
	}
	else
	{
		return eap_status_allocation_error;
	}
}

EAP_FUNC_EXPORT eap_type_saesim_triplet_c * eap_type_sim_triplet_array_c::add_triplet()
{
	eap_type_saesim_triplet_c **old_array = m_array;

	m_array = new eap_type_saesim_triplet_c *[m_triplet_count+1u];

	if (m_array != 0)
	{
		u32_t ind;

		for (ind = 0; ind < m_triplet_count; ind++)
		{
			m_array[ind] = old_array[ind];
		}

		delete [] old_array;
		++m_triplet_count;

		m_array[ind] = new eap_type_saesim_triplet_c(m_am_tools);
		if (m_array[ind] == 0)
		{
			return 0;
		}

		return m_array[ind];
	}
	else
	{
		m_array = old_array;
		return 0;
	}
}

EAP_FUNC_EXPORT eap_type_saesim_triplet_c * eap_type_sim_triplet_array_c::get_triplet(
	abs_eap_am_tools_c * const /* m_am_tools */, u32_t index)
{
	if (index < m_triplet_count)
	{
		return m_array[index];
	}
	else
	{
		EAP_ASSERT_ALWAYS(index < m_triplet_count);
		return 0;
	}
}

EAP_FUNC_EXPORT eap_status_e eap_type_sim_triplet_array_c::set_triplet(u32_t index, eap_type_saesim_triplet_c * const triplet)
{
	if (index < m_triplet_count)
	{
		if (m_array[index] != 0)
		{
			delete m_array[index];
		}
		m_array[index] = triplet;
		return eap_status_ok;
	}
	else
	{
		return eap_status_illegal_index;
	}
}

EAP_FUNC_EXPORT u32_t eap_type_sim_triplet_array_c::get_triplet_count()
{
	return m_triplet_count;
}

EAP_FUNC_EXPORT eap_type_sim_triplet_array_c * eap_type_sim_triplet_array_c::copy()
{
	eap_type_sim_triplet_array_c * const new_triplets
		= new eap_type_sim_triplet_array_c(m_am_tools);
	if (new_triplets == 0)
	{
		return 0;
	}

	eap_status_e status = new_triplets->set_triplet_count(get_triplet_count());
	if (status != eap_status_ok)
	{
		delete new_triplets;
		return 0;
	}

	for (u32_t ind = 0; ind < get_triplet_count(); ind++)
	{
		eap_status_e status = new_triplets->set_triplet(
			ind,
			get_triplet(m_am_tools, ind)->copy(m_am_tools));
		if (status != eap_status_ok)
		{
			delete new_triplets;
			return 0;
		}
	}

	return new_triplets;
}

EAP_FUNC_EXPORT void eap_type_sim_triplet_array_c::reset()
{
	if (m_array != 0)
	{
		for (u32_t ind = 0; ind < m_triplet_count; ind++)
		{
			delete m_array[ind];
			m_array[ind] = 0;
		}
		delete [] m_array;
		m_array = 0;
	}

	m_triplet_count = 0u;
	m_am_tools = 0;
}


//--------------------------------------------------



// End.
