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
	#define EAP_FILE_NUMBER_ENUM 65 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_type_aka_authentication_vector.h"
#include "eap_am_tools.h"

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_type_aka_authentication_vector_c::~eap_type_aka_authentication_vector_c()
{
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_type_aka_authentication_vector_c::eap_type_aka_authentication_vector_c(
	abs_eap_am_tools_c * const tools
	)
	: m_am_tools(tools)
	, m_RAND(tools)
	, m_AUTN(tools)
	, m_RES(tools)
	, m_CK(tools)
	, m_IK(tools)
	, m_AUTS(tools)
	, m_vector_status(eap_status_process_general_error)
	, m_is_valid(true)
{
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_type_aka_authentication_vector_c::get_RAND() const
{
	return const_cast<eap_variable_data_c *>(&m_RAND);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_type_aka_authentication_vector_c::get_AUTN() const
{
	return const_cast<eap_variable_data_c *>(&m_AUTN);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_type_aka_authentication_vector_c::get_RES() const
{
	return const_cast<eap_variable_data_c *>(&m_RES);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_type_aka_authentication_vector_c::get_CK() const
{
	return const_cast<eap_variable_data_c *>(&m_CK);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_type_aka_authentication_vector_c::get_IK() const
{
	return const_cast<eap_variable_data_c *>(&m_IK);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * eap_type_aka_authentication_vector_c::get_AUTS() const
{
	return const_cast<eap_variable_data_c *>(&m_AUTS);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_type_aka_authentication_vector_c * eap_type_aka_authentication_vector_c::copy() const
{
	eap_type_aka_authentication_vector_c * vector = new eap_type_aka_authentication_vector_c(m_am_tools);
	if (vector == 0)
	{
		return 0;
	}

	eap_status_e status = eap_status_process_general_error;

	if (get_RAND()->get_is_valid_data() == true)
	{
		status = vector->get_RAND()->set_copy_of_buffer(get_RAND());
		if (status != eap_status_ok)
		{
			vector->reset();
			delete vector;
			return 0;
		}
	}

	if (get_AUTN()->get_is_valid_data() == true)
	{
		status = vector->get_AUTN()->set_copy_of_buffer(get_AUTN());
		if (status != eap_status_ok)
		{
			vector->reset();
			delete vector;
			return 0;
		}
	}

	if (get_RES()->get_is_valid_data() == true)
	{
		status = vector->get_RES()->set_copy_of_buffer(get_RES());
		if (status != eap_status_ok)
		{
			vector->reset();
			delete vector;
			return 0;
		}
	}

	if (get_CK()->get_is_valid_data() == true)
	{
		status = vector->get_CK()->set_copy_of_buffer(get_CK());
		if (status != eap_status_ok)
		{
			vector->reset();
			delete vector;
			return 0;
		}
	}

	if (get_IK()->get_is_valid_data() == true)
	{
		status = vector->get_IK()->set_copy_of_buffer(get_IK());
		if (status != eap_status_ok)
		{
			vector->reset();
			delete vector;
			return 0;
		}
	}

	return vector;
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_type_aka_authentication_vector_c::reset()
{
	m_RAND.reset();
	m_AUTN.reset();
	m_RES.reset();
	m_CK.reset();
	m_IK.reset();
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_type_aka_authentication_vector_c::set_vector_status(eap_status_e vector_status)
{
	m_vector_status = vector_status;
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_aka_authentication_vector_c::get_vector_status() const
{
	return EAP_STATUS_RETURN(m_am_tools, m_vector_status);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_aka_authentication_vector_c::get_is_valid() const
{
	return m_is_valid;
}

//-------------------------------------------------------------------



// End.
