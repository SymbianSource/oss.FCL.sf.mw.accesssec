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
	#define EAP_FILE_NUMBER_ENUM 2 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "abs_eap_am_semaphore.h"

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT abs_eap_am_semaphore_c::~abs_eap_am_semaphore_c()
{
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT abs_eap_am_semaphore_c::abs_eap_am_semaphore_c()
{
}


// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_semaphore_reference_c::~eap_am_semaphore_reference_c()
{
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_semaphore_reference_c::eap_am_semaphore_reference_c()
	: m_reference_count(0u)
{
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT void eap_am_semaphore_reference_c::add_reference()
{
	++m_reference_count;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT void eap_am_semaphore_reference_c::remove_reference()
{
	--m_reference_count;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT u32_t eap_am_semaphore_reference_c::get_reference_count()
{
	return m_reference_count;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_semaphore_base_c::~eap_am_semaphore_base_c()
{
	if (m_reference != 0)
	{
		m_reference->remove_reference();

		if (m_reference->get_reference_count() == 0u)
		{
			delete m_reference;
		}
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_semaphore_base_c::eap_am_semaphore_base_c()
	: m_reference(0)
	, m_is_valid(false)
{
	m_reference = new eap_am_semaphore_reference_c();
	if (m_reference == 0)
	{
		return;
	}
	m_reference->add_reference();
	m_is_valid = true;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_semaphore_base_c::eap_am_semaphore_base_c(const eap_am_semaphore_base_c * const owner)
	: m_reference(0)
	, m_is_valid(false)
{
	m_reference = owner->get_reference();
	m_reference->add_reference();
	m_is_valid = true;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_semaphore_reference_c * eap_am_semaphore_base_c::get_reference() const
{
	return m_reference;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

/// Returns the validity of the semaphore.
EAP_FUNC_EXPORT bool eap_am_semaphore_base_c::get_is_valid() const
{
	return m_is_valid;
}

// ---------------------------------------------



// End.
