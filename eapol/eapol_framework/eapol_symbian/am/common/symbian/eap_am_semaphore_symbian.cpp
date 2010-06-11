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
	#define EAP_FILE_NUMBER_ENUM 146 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



// INCLUDES
#include "eap_am_memory.h"
#include "EapTraceSymbian.h"

#include "eap_am_semaphore_symbian.h"

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_semaphore_symbian_c::~eap_am_semaphore_symbian_c()
{
	m_semaphore.Close();
	m_owner_thread.Close();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_semaphore_symbian_c::eap_am_semaphore_symbian_c(
	const i32_t initial_count,
	const i32_t maximum_count)
	: m_count(initial_count)
	, m_is_valid(false)
{
	if (eap_am_semaphore_base_c::get_is_valid() == false)
	{
		return;
	}

	TInt err = m_semaphore.CreateLocal(initial_count);
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("\n ERROR: eap_am_semaphore_symbian_c::eap_am_semaphore_symbian_c : Semaphore CreateLocal returned err = %d"), err));
		return;
	}
	
	RThread thisThread; // Generic handle meaning "the current thread"

	err = thisThread.Duplicate(thisThread);    // a specific handle
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("\n ERROR: eap_am_semaphore_symbian_c::eap_am_semaphore_symbian_c : Thread Duplicate returned err = %d"), err));
		return;
	}

	m_owner_thread = thisThread;
	
	m_is_valid = true;	
}

EAP_FUNC_EXPORT eap_am_semaphore_symbian_c::eap_am_semaphore_symbian_c(
	const eap_am_semaphore_symbian_c * const owner)
	: eap_am_semaphore_base_c(owner)
	, m_count(0ul)
	, m_is_valid(false)
{
	if (eap_am_semaphore_base_c::get_is_valid() == false)
	{
		return;
	}
	
	m_semaphore = *(owner->get_semaphore());

	TInt err = m_semaphore.Duplicate(*(owner->get_owner_thread()));
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("\n ERROR: eap_am_semaphore_symbian_c::eap_am_semaphore_symbian_c(): Semaphore Duplicate returned err = %d"), err));
		return;
	}

	RThread thisThread; // Generic handle meaning "the current thread"  

	err = thisThread.Duplicate(thisThread);    // a specific handle 
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("\n ERROR: eap_am_semaphore_symbian_c::eap_am_semaphore_symbian_c(): Thread Duplicate returned err = %d"), err));
		return;
	}

	m_owner_thread = thisThread;
	
	m_is_valid = true;		
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const RSemaphore * eap_am_semaphore_symbian_c::get_semaphore() const
{
	return &m_semaphore;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const RThread * eap_am_semaphore_symbian_c::get_owner_thread() const
{
	return &m_owner_thread;
}

//--------------------------------------------------



EAP_FUNC_EXPORT eap_status_e eap_am_semaphore_symbian_c::semaphore_reserve()
{
	m_semaphore.Wait();
	m_count--;
	
	return eap_status_ok;
}

EAP_FUNC_EXPORT eap_status_e eap_am_semaphore_symbian_c::semaphore_release()
{
	m_count++;
	m_semaphore.Signal();
	
	return eap_status_ok;	
}

EAP_FUNC_EXPORT  abs_eap_am_semaphore_c * eap_am_semaphore_symbian_c::dublicate_semaphore()
{
	eap_am_semaphore_symbian_c *dublicate = new eap_am_semaphore_symbian_c(this);
	return dublicate;	
}

EAP_FUNC_EXPORT u32_t eap_am_semaphore_symbian_c::get_count() const
{
	return 	m_count;
}

EAP_FUNC_EXPORT bool eap_am_semaphore_symbian_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------




// End of file
