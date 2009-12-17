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
* Description:  Provide synch/asynch services used by the caller to show
*                EAP-TTLS-PAP related notes.
*
*/


#ifndef EAPTTLSPAPACTIVE_H
#define EAPTTLSPAPACTIVE_H


// INCLUDES
#include <utf.h>
#include <e32base.h>
#include <EapTtlsPapNotifierStruct.h>
#include <e32des16.h>
#include "EapTtlsPapDbInfoStruct.h"
#include "eap_status.h"

// FORWARD DECLARATIONS
class eap_am_type_tls_peap_symbian_c;
class eap_variable_data_c;
class eap_am_tools_symbian_c;

// CLASS DECLARATION
/**
* CEapTtlsPapActive class.
* 
* Class provides synch/asynch services used by the caller.
* These services includes:
* - query for TTLS-PAP user name and password.
*/
NONSHARABLE_CLASS( CEapTtlsPapActive )
    : public CActive
    {
    
    public: 
        /**
        * State defines the type of service called.
        */ 
        enum TEapTtlsPapActiveState
            {
            EEapTtlsPapActiveQueryUserNameAndPassword,          /* 0 */
            EEapTtlsPapActiveShowAuthQueryDialog,               /* 1 */
            EEapTtlsPapActiveShowPapChallengeMsgDialog,         /* 2 */
            EEapTtlsPapActiveShowPapChallengeReplyQueryDialog,  /* 3 */
            // ...
            EEapTtlsPapActiveStatesNumber                       /* 4 */ // keep always as last element
            };
                        
    public:  // Constructors and destructor

        /**
        * Two-phased constructor.
        *
        * @param aCaller Pointer AO owner.
        */
        static CEapTtlsPapActive* NewL(
        	eap_am_type_tls_peap_symbian_c* aCaller,
        	eap_am_tools_symbian_c* aAmTools );

        /**
        * Destructor.
        */
        ~CEapTtlsPapActive();
        

    public: // new

        /**
        * Start active object.
        *
        * @param aState State defines the type of service requested, see TEapTtlsPapActiveState.
		* @return TBool ETrue - successful start, EFalse - starting failed.
        */
        TBool Start( TEapTtlsPapActiveState aState );
                                   
        /**
        * Allocate server challenge.
        * 
        * Note, utf8->unicode conversion is needed.
        * 
        * @param aSrvChallenge Reference to server challenge.
        */
        eap_status_e UpdateSrvChallenge( const eap_variable_data_c& aSrvChallengeUtf8 );
    
    protected: // from CActive
    
        /**
        * DoCancel from CActive
        */    
        virtual void DoCancel();
      
        /**
        * RunL from CActive
        */      
        virtual void RunL();
    
    private: // new, for AO
          
        /**
        * Complete query-user-name-and-password request.
        */ 
        void CompleteQueryUserNameAndPassword();

        /**
        * Complete query-user-name-and-password request
        * with null server challenge.
        */ 
        void CompleteWithSrvChallengeNull();

        /**
        * Complete query-user-name-and-password request
        * with not null server challenge.
        */        
        void CompleteWithSrvChallengeNotNull();
        
        /**
        * Display authentication query dialog.
        * 
        * Note! The call is asynchronous, i.e., return is done immediately.
        */
        void StartAuthenticationQueryDialog();
    
        /**
        * Complete start-authentication-query-dialog request.
        * 
        * If user accepts query, the caller is notified with EEapTtlsPapNotifierUserActionOk
        * value. If user cancells the query,  EEapTtlsPapNotifierUserActionCancel
        * is given to the caller.
        */
        void CompleteAuthenticationQueryDialog();
        
        /**
        * Send server challenge data size to UI side.
        * 
        * Note! The call is asynchronous, i.e., return is done immediately.
        */
        void StartSrvChallengeSize();
        
        /**
        * Complete start-srv-challenge-size request.
        */        
        void CompleteSrvChallengeSize();
        
        /**
        * Display PAP challenge message dialog.
        * 
        * Note! The call is asynchronous, i.e., return is done immediately.
        */
        void StartPapChallengeMsgDialog();

        /**
        * Complete start-pap-challenge-msg-dialog request.
        */
        void CompletePapChallengeMsgDialog();

        /**
        * Display PAP challenge user reply query dialog.
        * 
        * Note! The call is asynchronous, i.e., return is done immediately.
        */
        void StartPapChallengeReplyQueryDialog();
        
        /**
        * Complete start-pap-challenge-user-reply-query-dialog request.
        */ 
        void CompletePapChallengeReplyQueryDialog();
    
    private: // new, other   
        
        /**
        * Take current time.
        * 
        * @return Current time, number of microseconds since midnight,
        *         January 1st, 0 AD nominal Gregorian.
        */ 
        TInt64 GetCurrentTime();
                
        /**
        * Cleans allocated memories and restores the initial object state.
        */
        void Clean();
    
    private: // private constructors

        /**
        * C++ default constructor.
        *
        * @param aCaller Pointer to AO owner.
        */
        CEapTtlsPapActive(
        	eap_am_type_tls_peap_symbian_c* aCaller,
        	eap_am_tools_symbian_c* aAmTools );
        
        /**
        * By default Symbian 2nd phase constructor is private.
        */
        void ConstructL();

    private: // data
    
        /**    
        * Object of this class implements functionality
        * of platform adaptation of Symbian.
        *
        *  Not owned.
        */
        eap_am_tools_symbian_c* iAmTools;
    
        /**
        * User / owner of this AO.
        * 
        * Not owned.
        */ 
        eap_am_type_tls_peap_symbian_c* iCaller ;
    
        /**
        * State defines the type of the requested service.
        */ 
        TEapTtlsPapActiveState iActiveState;
            
        /**
        * Notifier. It acts as a service provider.
        */
        RNotifier iNotifier; 
    
        /**
        * Data sent from AO to notifier plugin.
        *
        * If user name exists in database, it is sent to notifier.
        * Also could be used later, if server challenge is sent to UI
        * for displaying.
        */
        TPapUiNotifierInfo* iNotifierDataToUser;

        /**
        * Packaged data sent from AO to notifier plugin.
        */
        TPckg<TPapUiNotifierInfo>* iNotifierDataPckgToUser;	

        /**
        * Data from notifier plugin to AO.
        * Structure includes UI dialog id, user action value,
        * notifier buffer.
        */
        TPapUiNotifierInfo* iNotifierDataFromUser;

	    /**
        * Packaged data from notifier plugin to AO.
        */
	    TPckg<TPapUiNotifierInfo>* iNotifierDataPckgFromUser;	
       
	    /**
	    * Stores user action. Possible values are
	    * EPapNotifierUserActionOk and EPapNotifierUserActionCancel.
	    */
	    EPapNotifierUserAction iUserAction;
	    	    
	    /**
	    * Server challenge in unicode format.
	    */ 
	    HBufC16* iSrvChallengeUnicode;
	    
	    /**
	    * A pointer to the request status object.
	    */
	    TRequestStatus* iRequestStatus;

	    /**
	    * Structure contains database data for TTLS-PAP.
	    */ 
	    TTtlsPapDbInfo iTtlsPapDbInfo;
	    
	    /**
	    * Flag is needed to read database only once.
	    * ETrue - initialized, EFalse - not initialized.
	    */ 
	    TBool iIsTtlsPapDbInfoInitialized;
	    
	    /*
	    * Boolean flag to make sure that if objects are deleted in cancel,
	    * we don't use them anymore.
	    */
	    TBool iCancelCalled;
	    
    };

    
#endif // EAPTTLSPAPACTIVE_H

// End of File
