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

#if !defined( _ABS_EAP_AM_MUTEX_H_ )
#define _ABS_EAP_AM_MUTEX_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_MUTEX_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MUTEX_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MUTEX_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_MUTEX_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MUTEX_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MUTEX_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MUTEX_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MUTEX_H 
#endif
// End: added by script change_export_macros.sh.

class eap_am_mutex_reference_c;

// ---------------------------------------------

/// This class is interface to mutex.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_MUTEX_H abs_eap_am_mutex_c
{
private:

public:

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual ~abs_eap_am_mutex_c();

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H abs_eap_am_mutex_c();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function enters the mutex. Thread will block until the mutex is released
	 * by other owner of the mutex.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual eap_status_e mutex_enter() = 0;

	/**
	 * This function leaves the mutex. Other blocking thread will continue execution.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual eap_status_e mutex_leave(abs_eap_am_tools_c * const m_am_tools) = 0;

	/**
	 * The mutex handle must be dublicated in Symbian operating system for each thread.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual abs_eap_am_mutex_c * dublicate_mutex() = 0;

	/**
	 * This function returns the flag that indicates whether the mutex is reserved. 
	 * This is used in debug asserts. Those will check the mutex is really reserved when critical code is entered.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual bool get_is_reserved() const = 0;

	/**
	 * Returns the validity of the mutex.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual bool get_is_valid() const = 0;

#if defined(USE_EAPOL_MUTEX_SEMAPHORE_TRACES)
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual eap_am_mutex_reference_c * get_reference() const = 0;
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual void set_am_tools(abs_eap_am_tools_c * const tools) = 0;
#endif //#if defined(USE_EAPOL_MUTEX_SEMAPHORE_TRACES)

	// - - - - - - - - - - - - - - - - - - - - - - - -

};

// ---------------------------------------------

/// This class defines a reference counter of a mutex.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_MUTEX_H eap_am_mutex_reference_c
{

private:

	/// This is the reference count to the mutex.
	u32_t m_reference_count;

	/// This flag indicates whether the mutex is reserved. 
	/// This is used in debug asserts. Those will check the mutex is really reserved when critical code is entered.
	bool m_is_reserved;

	// On purpose unimplemented constructors.
	eap_am_mutex_reference_c(eap_am_mutex_reference_c &source);
	const eap_am_mutex_reference_c & operator=(const eap_am_mutex_reference_c& source);

public:

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual ~eap_am_mutex_reference_c();

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H eap_am_mutex_reference_c();

	/**
	 * This function adds one reference to the mutex. 
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H void add_reference();

	/**
	 * This function removes one reference to the mutex. 
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H void remove_reference();

	/**
	 * This function returns the reference count of the mutex. 
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H u32_t get_reference_count();

	/**
	 * This function sets the flag that indicates whether the mutex is reserved. 
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H void set_is_reserved(const bool is_reserved);

	/**
	 * This function returns the flag that indicates whether the mutex is reserved. 
	 * This is used in debug asserts. Those will check the mutex is really reserved when critical code is entered.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H bool get_is_reserved();
};

// ---------------------------------------------

/// This class is base of the mutex.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_MUTEX_H eap_am_mutex_base_c
{
private:

	eap_am_mutex_reference_c * m_reference;

	bool m_is_valid;

	// On purpose unimplemented constructors.
	eap_am_mutex_base_c(eap_am_mutex_base_c &source);
	const eap_am_mutex_base_c & operator=(const eap_am_mutex_base_c& source);

public:

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H virtual ~eap_am_mutex_base_c();

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H eap_am_mutex_base_c();

	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H eap_am_mutex_base_c(const eap_am_mutex_base_c * const owner);

	/**
	 * This function returns pointer to the reference counter object of the mutex.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H eap_am_mutex_reference_c * get_reference() const;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the flag that indicates whether the mutex is reserved. 
	 * This is used in debug asserts. Those will check the mutex is really reserved when critical code is entered.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H bool get_is_reserved() const;

	/**
	 * Returns the validity of the mutex.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MUTEX_H bool get_is_valid() const;

	// - - - - - - - - - - - - - - - - - - - - - - - -

};

// ---------------------------------------------

#endif //#if !defined( _ABS_EAP_AM_MUTEX_H_ )



// End.
