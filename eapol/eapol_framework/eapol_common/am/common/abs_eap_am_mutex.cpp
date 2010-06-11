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
	#define EAP_FILE_NUMBER_ENUM 1 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "abs_eap_am_mutex.h"

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT abs_eap_am_mutex_c::~abs_eap_am_mutex_c()
{
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT abs_eap_am_mutex_c::abs_eap_am_mutex_c()
{
}


// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_mutex_reference_c::~eap_am_mutex_reference_c()
{
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_mutex_reference_c::eap_am_mutex_reference_c()
	: m_reference_count(0u)
	, m_is_reserved(false)
{
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT void eap_am_mutex_reference_c::add_reference()
{
	++m_reference_count;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT void eap_am_mutex_reference_c::remove_reference()
{
	--m_reference_count;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT u32_t eap_am_mutex_reference_c::get_reference_count()
{
	return m_reference_count;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT void eap_am_mutex_reference_c::set_is_reserved(const bool is_reserved)
{
	m_is_reserved = is_reserved;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT bool eap_am_mutex_reference_c::get_is_reserved()
{
#if defined(NO_EAP_MUTEX)
	return true;
#else
	return m_is_reserved;
#endif
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_mutex_base_c::~eap_am_mutex_base_c()
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

EAP_FUNC_EXPORT eap_am_mutex_base_c::eap_am_mutex_base_c()
	: m_reference(0)
	, m_is_valid(false)
{
	m_reference = new eap_am_mutex_reference_c();
	if (m_reference == 0)
	{
		return;
	}
	m_reference->add_reference();
	m_is_valid = true;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_mutex_base_c::eap_am_mutex_base_c(const eap_am_mutex_base_c * const owner)
	: m_reference(0)
	, m_is_valid(false)
{
	m_reference = owner->get_reference();
	m_reference->add_reference();
	m_is_valid = true;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

EAP_FUNC_EXPORT eap_am_mutex_reference_c * eap_am_mutex_base_c::get_reference() const
{
	return m_reference;
}

// - - - - - - - - - - - - - - - - - - - - - - - -

/// This function is used in debug asserts.
/// Those will check the mutex is really reserved when critical code is entered.
EAP_FUNC_EXPORT bool eap_am_mutex_base_c::get_is_reserved() const
{
	// In Symbian we need this object to test reference flag,
	// because each thread has own duplicated mutex object.
	return m_reference->get_is_reserved();
}

// - - - - - - - - - - - - - - - - - - - - - - - -

/// Returns the validity of the mutex.
EAP_FUNC_EXPORT bool eap_am_mutex_base_c::get_is_valid() const
{
	return m_is_valid;
}

// ---------------------------------------------



// End.
