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
	#define EAP_FILE_NUMBER_ENUM 602 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



// INCLUDES
#include "eap_am_memory.h"
#include "eap_am_mutex_symbian.h"
#include "abs_eap_am_mutex.h"

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_mutex_symbian_c::~eap_am_mutex_symbian_c()
{
	m_mutex.Close();
	m_owner_thread.Close();
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_mutex_symbian_c::eap_am_mutex_symbian_c()
	: m_is_valid(false)
{
	if (eap_am_mutex_base_c::get_is_valid() == false)
	{
		return;
	}

	m_mutex.CreateLocal();

	RThread thisThread; // Generic handle meaning "the current thread"

	TInt err = thisThread.Duplicate(thisThread);    // a specific handle
	if (err == KErrNone)
	{
		m_is_valid = true;
	}

	m_owner_thread = thisThread;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_mutex_symbian_c::eap_am_mutex_symbian_c(const eap_am_mutex_symbian_c * const owner)
	: eap_am_mutex_base_c(owner)
	, m_is_valid(false)
{
	if (eap_am_mutex_base_c::get_is_valid() == false)
	{
		return;
	}

	m_mutex = *(owner->get_mutex());
	m_mutex.Duplicate(*(owner->get_owner_thread()));

	RThread thisThread; // Generic handle meaning "the current thread"  

	TInt err = thisThread.Duplicate(thisThread);    // a specific handle 
	if (err == KErrNone)
	{
		m_is_valid = true;
	}

	m_owner_thread = thisThread;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const RMutex * eap_am_mutex_symbian_c::get_mutex() const
{
	return &m_mutex;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const RThread * eap_am_mutex_symbian_c::get_owner_thread() const
{
	return &m_owner_thread;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_mutex_symbian_c::mutex_enter()
{
#if !defined(NO_EAP_MUTEX)
	m_mutex.Wait();
	get_reference()->set_is_reserved(true);
#endif //#if !defined(NO_EAP_MUTEX)

	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_mutex_symbian_c::mutex_leave(abs_eap_am_tools_c * const m_am_tools)
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

#if !defined(NO_EAP_MUTEX)
	EAP_ASSERT(get_reference()->get_is_reserved() == true);

	get_reference()->set_is_reserved(false);
	m_mutex.Signal();
#endif //#if !defined(NO_EAP_MUTEX)

	return eap_status_ok;
}

//--------------------------------------------------

//
// The mutex handle must be dublicated in Symbian operating system for each thread.
EAP_FUNC_EXPORT abs_eap_am_mutex_c * eap_am_mutex_symbian_c::dublicate_mutex()
{
	eap_am_mutex_symbian_c *dublicate = new eap_am_mutex_symbian_c(this);
	return dublicate;
}

//--------------------------------------------------

//
// This is used in debug asserts. Those will check the mutex is really reserved when critical code is entered.
EAP_FUNC_EXPORT bool eap_am_mutex_symbian_c::get_is_reserved() const
{
	// In Symbian we need this object to test reference flag,
	// because each thread has own duplicated mutex object.
	return get_reference()->get_is_reserved();
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_mutex_symbian_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------



// End of file
