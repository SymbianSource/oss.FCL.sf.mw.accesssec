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
* %version: 4 %
*/

#ifndef _EAP_AM_ASYNC_WAIT_SYMBIAN_H_
#define _EAP_AM_ASYNC_WAIT_SYMBIAN_H_


/**
 * eap_am_async_wait_symbian_c class
 */
 
class eap_am_async_wait_symbian_c : public CActive
    {
    public: 

        /**
        * C++ default constructor.
        */
        eap_am_async_wait_symbian_c();
        
        /**
        * Destructor.
        */    
        ~eap_am_async_wait_symbian_c() ;

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
