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

#if !defined( _EAP_AM_MUTEX_SYMBIAN_H_ )
#define _EAP_AM_MUTEX_SYMBIAN_H_

// INCLUDES
#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_MUTEX_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_MUTEX_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MUTEX_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_MUTEX_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MUTEX_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MUTEX_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MUTEX_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MUTEX_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_mutex.h"

// CLASS DECLARATION
class EAP_CLASS_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H eap_am_mutex_symbian_c
: public abs_eap_am_mutex_c
, public eap_am_mutex_base_c
{
private:

	/// Object is Symbian implementation of the mutex.
	RMutex m_mutex;

	/// Object is Symbian implementation of the thread which is owner of the mutex.
	RThread m_owner_thread;

	bool m_is_valid;

	// On purpose unimplemented constructors.
	eap_am_mutex_symbian_c(eap_am_mutex_symbian_c &source);
	const eap_am_mutex_symbian_c & operator=(const eap_am_mutex_symbian_c& source);

public:

	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H virtual ~eap_am_mutex_symbian_c();

	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H eap_am_mutex_symbian_c();

	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H eap_am_mutex_symbian_c(const eap_am_mutex_symbian_c * const owner);

	/// Function returns pointer to Symbian mutex.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H const RMutex * get_mutex() const;

	/// Function returns pointer to owner thread of the mutex.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H const RThread * get_owner_thread() const;

	// See comments on abs_eap_am_mutex_c.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H eap_status_e mutex_enter();

	// See comments on abs_eap_am_mutex_c.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H eap_status_e mutex_leave(abs_eap_am_tools_c * const m_am_tools);

	// The mutex handle must be dublicated in Symbian operating system for each thread.
	// See comments on abs_eap_am_mutex_c.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H abs_eap_am_mutex_c * dublicate_mutex();

	// This is used in debug asserts. Those will check the mutex is really reserved when critical code is entered.
	// See comments on abs_eap_am_mutex_c.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H bool get_is_reserved() const;

	// See comments on abs_eap_am_mutex_c.
	EAP_FUNC_VISIBILITY_EAP_AM_MUTEX_SYMBIAN_H bool get_is_valid() const;

	// - - - - - - - - - - - - - - - - - - - - - - - -

};

#endif //#if !defined( _EAP_AM_MUTEX_SYMBIAN_H_ )



// End of file
