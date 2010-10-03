/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 2.1.3 %
*/

#ifndef _EAP_AM_ASYNC_WAIT_SYMBIAN_H_
#define _EAP_AM_ASYNC_WAIT_SYMBIAN_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_ASYNC_WAIT_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.

/**
 * eap_am_async_wait_symbian_c class
 */
 
class EAP_CLASS_VISIBILITY_EAP_AM_ASYNC_WAIT_SYMBIAN_H eap_am_async_wait_symbian_c : public CActive
    {
    public: 

        /**
        * C++ default constructor.
        */
        eap_am_async_wait_symbian_c();
        
        /**
        * Destructor.
        */    
        virtual ~eap_am_async_wait_symbian_c() ;

    public: 

        /**
        * Nested scheduler loop
        */
        void Wait() ;

    private: // CActive

        void RunL();
        void DoCancel();


    private: // data

        CActiveSchedulerWait iActiveWait ; // nested loop for active scheduler
} ;

#endif // _EAP_AM_ASYNC_WAIT_SYMBIAN_H_
