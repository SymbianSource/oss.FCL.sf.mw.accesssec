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




#if !defined( _ABS_EAP_AM_SEMAPHORE_H_ )
#define _ABS_EAP_AM_SEMAPHORE_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"

class eap_am_semaphore_reference_c;

// ---------------------------------------------

/// This class is interface to semaphore.
class EAP_EXPORT abs_eap_am_semaphore_c
{
private:

public:

	EAP_FUNC_IMPORT virtual ~abs_eap_am_semaphore_c();

	EAP_FUNC_IMPORT abs_eap_am_semaphore_c();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function reserves the semaphore. Thread will block until the semaphore is released
	 * by other owner of the semaphore.
	 */
	EAP_FUNC_IMPORT virtual eap_status_e semaphore_reserve() = 0;

	/**
	 * This function releases the semaphore. Other blocking thread will continue execution.
	 */
	EAP_FUNC_IMPORT virtual eap_status_e semaphore_release() = 0;

	/**
	 * The semaphore handle must be dublicated in Symbian operating system for each thread.
	 */
	EAP_FUNC_IMPORT virtual abs_eap_am_semaphore_c * dublicate_semaphore() = 0;

	EAP_FUNC_IMPORT virtual u32_t get_count() const = 0;

	/**
	 * Returns the validity of the semaphore.
	 */
	EAP_FUNC_IMPORT virtual bool get_is_valid() const = 0;

#if defined(USE_EAPOL_MUTEX_SEMAPHORE_TRACES)
	EAP_FUNC_IMPORT virtual eap_am_semaphore_reference_c * get_reference() const = 0;
	EAP_FUNC_IMPORT virtual void set_am_tools(abs_eap_am_tools_c * const tools) = 0;
#endif //#if defined(USE_EAPOL_MUTEX_SEMAPHORE_TRACES)

	// - - - - - - - - - - - - - - - - - - - - - - - -

};

// ---------------------------------------------

/// This class defines a reference counter of a semaphore.
class EAP_EXPORT eap_am_semaphore_reference_c
{

private:

	/// This is the reference count to the semaphore.
	u32_t m_reference_count;

public:

	EAP_FUNC_IMPORT virtual ~eap_am_semaphore_reference_c();

	EAP_FUNC_IMPORT eap_am_semaphore_reference_c();

	EAP_FUNC_IMPORT void add_reference();

	EAP_FUNC_IMPORT void remove_reference();

	EAP_FUNC_IMPORT u32_t get_reference_count();
};

// ---------------------------------------------

/// This class is base of the semaphore.
class EAP_EXPORT eap_am_semaphore_base_c
{
private:

	eap_am_semaphore_reference_c * m_reference;

	bool m_is_valid;

public:

	EAP_FUNC_IMPORT virtual ~eap_am_semaphore_base_c();

	EAP_FUNC_IMPORT eap_am_semaphore_base_c();

	EAP_FUNC_IMPORT eap_am_semaphore_base_c(const eap_am_semaphore_base_c * const owner);

	EAP_FUNC_IMPORT eap_am_semaphore_reference_c * get_reference() const;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// Returns the validity of the semaphore.
	EAP_FUNC_IMPORT bool get_is_valid() const;

	// - - - - - - - - - - - - - - - - - - - - - - - -

};

// ---------------------------------------------

#endif //#if !defined( _ABS_EAP_AM_SEMAPHORE_H_ )



// End.
