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


// INCLUDE FILES
#include "eap_tools.h"
#include "eap_ttls_pap_active.h"
#include "eap_am_type_tls_peap_symbian.h"
#include "eap_am_trace_symbian.h"
#include "eap_variable_data.h"

// ================= public:  Constructors and destructor =======================

// ---------------------------------------------------------
// CEapTtlsPapActive::NewL()
// ---------------------------------------------------------
//
CEapTtlsPapActive* CEapTtlsPapActive::NewL(
    eap_am_type_tls_peap_symbian_c* aCaller,
    eap_am_tools_symbian_c* aAmTools )
    {
    DEBUG( "CEapTtlsPapActive::NewL()" );
    CEapTtlsPapActive* self = new(ELeave) CEapTtlsPapActive(
    	aCaller, aAmTools );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop();
    return self;
    }

// ---------------------------------------------------------
// CEapTtlsPapActive::~CEapTtlsPapActive()
// ---------------------------------------------------------
//    
CEapTtlsPapActive::~CEapTtlsPapActive()
    {
    DEBUG( "CEapTtlsPapActive::~CEapTtlsPapActive()" );	
	if ( !iCancelCalled )
	    {
	    Clean();
	   	}
    }

// ================= public:  new =======================

// ---------------------------------------------------------
// CEapTtlsPapActive::Start()
// ---------------------------------------------------------
//    
TBool CEapTtlsPapActive::Start( TEapTtlsPapActiveState aState )
    {
    DEBUG1( "CEapTtlsPapActive::Start() aState=%d.", aState );
    TBool status = ETrue;

    if( IsActive() )
		{
		DEBUG2( "CEapTtlsPapActive::Start() ERROR: AO is active, iActiveState=%d, aState=%d.",
            iActiveState, aState );
		return EFalse;
		}
	if ( iCancelCalled )
		{
		DEBUG( "CEapTtlsPapActive::Start() cancel was called." );
		return EFalse;
		}
    iActiveState = aState;    
    switch ( iActiveState )
        {
        case EEapTtlsPapActiveQueryUserNameAndPassword:
        	{
        	// nothing to do here, we should return asap;
        	// the job is done in RunL() method;
        	// therefore we complete here
        	SetActive();    
            iRequestStatus = &iStatus;
            User::RequestComplete( iRequestStatus, KErrNone );
            break;
        	}
        case EEapTtlsPapActiveShowAuthQueryDialog: // asynch. call
        	{
        	StartAuthenticationQueryDialog();
            SetActive();
        	break;
        	}        	
        case EEapTtlsPapActiveShowPapChallengeMsgDialog:
        	{
        	StartPapChallengeMsgDialog();
        	SetActive();
        	break;
        	}
        case EEapTtlsPapActiveShowPapChallengeReplyQueryDialog:
        	{
        	StartPapChallengeReplyQueryDialog();
        	SetActive();
        	break;
        	}
        default:
        	{
    		DEBUG1( "CEapTtlsPapActive::Start() ERROR: State is not supported, iActiveState = %d.",
    	            iActiveState );
    		status = EFalse;
            break;
        	}
        }
    return status;
    } // EapTtlsPapActive::Start()


// ---------------------------------------------------------
// CEapTtlsPapActive::UpdateSrvChallenge()
// ---------------------------------------------------------
// 
eap_status_e CEapTtlsPapActive::UpdateSrvChallenge(
	const eap_variable_data_c& aSrvChallengeUtf8 )
	{
	DEBUG( "CEapTtlsPapActive::UpdateSrvChallenge()" );

	eap_status_e status = eap_status_ok;
	
	if ( iSrvChallengeUnicode != NULL )
		{
		// delete
		delete iSrvChallengeUnicode ;
		iSrvChallengeUnicode = NULL;
		}
	// convert utf8->unicode,
	// aSrvChallengeUtf8 is UTF8 string, unicode max length is
	// then the length of UTF8 string.
	// NOTE, HBufC16 length means count of 16-bit objects.
	TRAPD( err, iSrvChallengeUnicode = HBufC16::NewL( aSrvChallengeUtf8.get_data_length() ); );
	if ( err != KErrNone )
	    {
		status = iCaller->ConvertAmErrorToEapolError( err );
		return status;
	    } 
	TPtr16 srvChallengeUnicodePtr = iSrvChallengeUnicode->Des();

	const TPtrC8 ptrUtf8(
		aSrvChallengeUtf8.get_data( aSrvChallengeUtf8.get_data_length() ),
		aSrvChallengeUtf8.get_data_length() ); // Length in bytes

	CnvUtfConverter::ConvertToUnicodeFromUtf8(
		srvChallengeUnicodePtr, ptrUtf8 );
	// print data
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
		EAPL( "iSrvChallengeUnicode" ),
		iSrvChallengeUnicode->Ptr(),
		iSrvChallengeUnicode->Size() ) );
	
	return status;
	}


// ================= protected: from CActive =======================

// ---------------------------------------------------------
// CEapTtlsPapActive::DoCancel()
// ---------------------------------------------------------
// 
void CEapTtlsPapActive::DoCancel()
    {
    DEBUG( "CEapTtlsPapActive::DoCancel()" );
    DEBUG( "CEapTtlsPapActive::DoCancel() iNotifier.CancelNotifier() called." );
	iNotifier.CancelNotifier( KPapNotifierUid );
    }
 
// ---------------------------------------------------------
// CEapTtlsPapActive::RunL()
// ---------------------------------------------------------
//     
void CEapTtlsPapActive::RunL()
    {
    DEBUG1( "CEapTtlsPapActive::RunL() iStatus=%d", iStatus.Int() );
    
    switch ( iActiveState )
        {
        case EEapTtlsPapActiveQueryUserNameAndPassword:
        	{
        	CompleteQueryUserNameAndPassword();
        	break;
        	}
        case EEapTtlsPapActiveShowAuthQueryDialog:
    	    {
    	    CompleteAuthenticationQueryDialog();
    	    break;
    	    }	    
        case EEapTtlsPapActiveShowPapChallengeMsgDialog:
        	{
        	CompletePapChallengeMsgDialog();
        	break;
        	}
        case EEapTtlsPapActiveShowPapChallengeReplyQueryDialog:
        	{
        	CompletePapChallengeReplyQueryDialog();
        	break;
        	}
        default:
        	{
    		DEBUG1( "CEapTtlsPapActive::RunL() ERROR: State is not supported, iActiveState = %d.",
    	            iActiveState);
            break;
        	}
        }
    }

// ================= private: new, for AO =======================
   
// ---------------------------------------------------------
// CEapTtlsPapActive::CompleteQueryUserNameAndPassword()
// ---------------------------------------------------------
//    
void CEapTtlsPapActive::CompleteQueryUserNameAndPassword()
	{
	DEBUG( "CEapTtlsPapActive::CompleteQueryUserNameAndPassword()" );	
    
	if ( iSrvChallengeUnicode == NULL )
		{
		CompleteWithSrvChallengeNull();
		}
	else
		{
		CompleteWithSrvChallengeNotNull();
		}	
	} // CEapTtlsPapActive::CompleteQueryUserNameAndPassword()


// ---------------------------------------------------------
// CEapTtlsPapActive::CompleteWithSrvChallengeNull()
// ---------------------------------------------------------
//    
void CEapTtlsPapActive::CompleteWithSrvChallengeNull()
	{
	DEBUG( "CEapTtlsPapActive::CompleteWithSrvChallengeNull()" );	

	if ( !iCaller )
		{
		DEBUG( "CEapTtlsPapActive::CompleteWithSrvChallengeNull() ERROR: iCaller==NULL." );	
		return;
		}
	
	if ( !iIsTtlsPapDbInfoInitialized )
		{
	    // Read prompt, user name, password, and time stamps from database.
	    TRAPD( err,  iCaller->ReadTtlsPapDbL( iTtlsPapDbInfo ) );	
	    if ( err != KErrNone )
		    {
		    DEBUG1( "CEapTtlsPapActive::CompleteWithSrvChallengeNull() \
			    ERROR: Leave, err==%d.", err );			
		    iCaller->CompleteQueryTtlsPapUserNameAndPassword(
			    iCaller->ConvertAmErrorToEapolError( err ),
			    KNullDesC8(), KNullDesC8() );
		    return;
		    }
	    iIsTtlsPapDbInfoInitialized = ETrue;
		}
	
    if ( iTtlsPapDbInfo.iUsrPwdInfo.iPasswordPromptEnabled )
    	{
    	// set password to null value
    	TRAPD(err, iCaller->SetTtlsPapColumnToNullL( cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ));

    	if (err != KErrNone)
    	    {
    	    DEBUG1( "CEapTtlsPapActive::CompleteWithSrvChallengeNull() \
    	        ERROR: Leave, err==%d.", err );         
    	    iCaller->CompleteQueryTtlsPapUserNameAndPassword(
    	        iCaller->ConvertAmErrorToEapolError( err ),
    	        KNullDesC8(), KNullDesC8() );
    	    return;
    	    }

    	// display query dialog
    	Start( EEapTtlsPapActiveShowAuthQueryDialog );
    	}
    else // prompt not active
    	{
    	if ( iTtlsPapDbInfo.iUsrPwdInfo.iUserName.Length() != 0  &&
    		 iTtlsPapDbInfo.iUsrPwdInfo.iPassword.Length() != 0  )
    		{
            // complete query with user name and password from database;
    		// first, convert from unicode to utf8.
        	TBuf8<KMaxPapUserNameLength> userNameUtf8;
        	CnvUtfConverter::ConvertFromUnicodeToUtf8( userNameUtf8,
        		iTtlsPapDbInfo.iUsrPwdInfo.iUserName );
        	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
        		EAPL( "userNameUtf8" ),
        		userNameUtf8.Ptr(),
        		userNameUtf8.Size() ) );

        	TBuf8<KMaxPapPasswordLength> passwordUtf8;
        	CnvUtfConverter::ConvertFromUnicodeToUtf8( passwordUtf8,
        		iTtlsPapDbInfo.iUsrPwdInfo.iPassword );   	
        	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
        		EAPL( "passwordUtf8" ),
        		passwordUtf8.Ptr(),
        		passwordUtf8.Size() ) );
       	
        	iCaller->CompleteQueryTtlsPapUserNameAndPassword(
            	eap_status_ok, userNameUtf8, passwordUtf8 );    		
    		}
    	else // user name or password is empty
    		{
        	// display query dialog
        	Start( EEapTtlsPapActiveShowAuthQueryDialog );
    		}   	
    	} // if ( iPrompt )
	} // CEapTtlsPapActive::CompleteWithSrvChallengeNull()

// ---------------------------------------------------------
// CEapTtlsPapActive::CompleteWithSrvChallengeNotNull()
// ---------------------------------------------------------
//    
void CEapTtlsPapActive::CompleteWithSrvChallengeNotNull()
	{
	DEBUG( "CEapTtlsPapActive::CompleteWithSrvChallengeNotNull()" );	
	if ( !iCaller )
		{
		DEBUG( "CEapTtlsPapActive::CompleteWithSrvChallengeNotNull() ERROR: iCaller==NULL." );	
		return;
		}
	
	if ( !iIsTtlsPapDbInfoInitialized )
		{
	    // Read prompt, user name, password, and time stamps from database.
	    TRAPD( err,  iCaller->ReadTtlsPapDbL( iTtlsPapDbInfo ) );	
	    if ( err != KErrNone )
		    {
		    DEBUG1( "CEapTtlsPapActive::CompleteWithSrvChallengeNotNull() \
			    ERROR: Leave, err==%d.", err );			
		    iCaller->CompleteQueryTtlsPapUserNameAndPassword(
			    iCaller->ConvertAmErrorToEapolError( err ),
			    KNullDesC8(), KNullDesC8() );
		    return;
		    }
	    iIsTtlsPapDbInfoInitialized = ETrue;
		}
	
	// display PAP challenge message dialog
	Start( EEapTtlsPapActiveShowPapChallengeMsgDialog );
	} // CEapTtlsPapActive::CompleteWithSrvChallengeNotNull()

// ---------------------------------------------------------
// CEapTtlsPapActive::StartAuthenticationQueryDialog()
// ---------------------------------------------------------
//    
void CEapTtlsPapActive::StartAuthenticationQueryDialog()
	{
	DEBUG( "CEapTtlsPapActive::StartAuthenticationQueryDialog()" );
	
	if ( iNotifierDataPckgToUser == NULL ||
		 iNotifierDataPckgFromUser == NULL ||
		 iNotifierDataToUser == NULL ||
		 iNotifierDataFromUser == NULL )
		{
		DEBUG( "CEapTtlsPapActive::StartAuthenticationQueryDialog() \
				ERROR: data pointer is NULL." );
		return;
		}
	
	// set user name, copy data
	( *iNotifierDataPckgToUser )().iUsrPwdInfo.iUserName = iTtlsPapDbInfo.iUsrPwdInfo.iUserName;
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
		EAPL( "iUserName" ),
		iTtlsPapDbInfo.iUsrPwdInfo.iUserName.Ptr(),
		iTtlsPapDbInfo.iUsrPwdInfo.iUserName.Size() ) );
		
	iNotifierDataToUser->iState = TPapUiNotifierInfo::
	    EPapUiNotifierAuthQueryDialog;
	iNotifier.StartNotifierAndGetResponse( 
        iStatus,
        KPapNotifierUid,
        *iNotifierDataPckgToUser,
		*iNotifierDataPckgFromUser );
   	} // CEapTtlsPapActive::StartAuthenticationQueryDialog()

// ---------------------------------------------------------
// CEapTtlsPapActive::CompleteAuthenticationQueryDialog()
// ---------------------------------------------------------
// 
// called in RunL()
void CEapTtlsPapActive::CompleteAuthenticationQueryDialog()
	{
	DEBUG( "CEapTtlsPapActive::CompleteAuthenticationQueryDialog()" );
	
    if ( iStatus == KErrNone )
    	{
    	iUserAction = EPapNotifierUserActionOk;
    	}
    else if ( iStatus == KErrCancel )
		{
		iUserAction = EPapNotifierUserActionCancel;	
		}		
	else
		{
	    DEBUG1( "CEapTtlsPapActive::CompleteAuthenticationQueryDialog() \
	        ERROR: iStatus=%d", iStatus.Int() );
		return;
		}
    DEBUG1( "CEapTtlsPapActive::CompleteAuthenticationQueryDialog() \
        iUserAction=%d", iStatus.Int() );   
	
	if ( !iCaller )
		{
		DEBUG( "CEapTtlsPapActive::CompleteAuthenticationQueryDialog() \
	        ERROR: iCaller==NULL." );
		return;
		}
	if ( !iNotifierDataFromUser )
		{
		DEBUG( "CEapTtlsPapActive::CompleteAuthenticationQueryDialog() \
            ERROR: iNotifierDataFromUser==NULL." );		
		return;
		}
	if ( iUserAction == EPapNotifierUserActionOk )
		{		
		// just update last cache time in db
		iTtlsPapDbInfo.iLastFullAuthTime = GetCurrentTime();	
		
		if ( !iTtlsPapDbInfo.iUsrPwdInfo.iPasswordPromptEnabled )
			{
			// prompt is not active;
			// update user name, and password
			iTtlsPapDbInfo.iUsrPwdInfo.iUserName = iNotifierDataFromUser->
			    iUsrPwdInfo.iUserName;
			iTtlsPapDbInfo.iUsrPwdInfo.iPassword = iNotifierDataFromUser->
			    iUsrPwdInfo.iPassword;			
			}
		
		// update database
	    TRAPD( err, iCaller->WriteTtlsPapDbL( iTtlsPapDbInfo ) );

	    if (err != KErrNone)
	        {
	        DEBUG1( "CEapTtlsPapActive::CompleteAuthenticationQueryDialog() \
	            ERROR: Leave, err==%d.", err );         
	        iCaller->CompleteQueryTtlsPapUserNameAndPassword(
	            iCaller->ConvertAmErrorToEapolError( err ),
	            KNullDesC8(), KNullDesC8() );
	        return;
	        }
		
        // convert from unicode to utf8
		TBuf8<KMaxPapUserNameLength> userNameUtf8;
    	CnvUtfConverter::ConvertFromUnicodeToUtf8( userNameUtf8,
    		iNotifierDataFromUser->iUsrPwdInfo.iUserName );
    	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
    		EAPL( "userNameUtf8" ),
    		userNameUtf8.Ptr(),
    		userNameUtf8.Size() ) );

    	TBuf8<KMaxPapPasswordLength> passwordUtf8;
    	CnvUtfConverter::ConvertFromUnicodeToUtf8( passwordUtf8,
    		iNotifierDataFromUser->iUsrPwdInfo.iPassword );   	
    	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
    		EAPL( "passwordUtf8" ),
    		passwordUtf8.Ptr(),
    		passwordUtf8.Size() ) );
   	
    	// complete query with user name and password from UI
    	iCaller->CompleteQueryTtlsPapUserNameAndPassword(
        	eap_status_ok, userNameUtf8, passwordUtf8 );
		}
  	else //if (userAction == EPapNotifierUserActionCancel)
  		{
  		// user name and password are not used
		iCaller->CompleteQueryTtlsPapUserNameAndPassword(
			eap_status_user_cancel_authentication,
			KNullDesC8(),
			KNullDesC8() );
  		} 
	} // CEapTtlsPapActive::CompleteAuthenticationQueryDialog()


// ---------------------------------------------------------
// CEapTtlsPapActive::StartPapChallengeMsgDialog()
// ---------------------------------------------------------
// 
void CEapTtlsPapActive::StartPapChallengeMsgDialog()
	{
	DEBUG( "CEapTtlsPapActive::StartPapChallengeMsgDialog()" );
	
	if ( iNotifierDataPckgToUser == NULL ||
		 iNotifierDataPckgFromUser == NULL ||
		 iNotifierDataToUser == NULL ||
		 iNotifierDataFromUser == NULL )
		{
		DEBUG( "CEapTtlsPapActive::StartPapChallengeMsgDialog() \
				ERROR: data pointer is NULL." );
		return;
		}	

	TPtrC16 ptr = iSrvChallengeUnicode->Des();
	iNotifierDataToUser->iSrvChallengeSize = ptr.Size(); // number of bytes
			
	iNotifierDataToUser->iState = TPapUiNotifierInfo::
	    EPapUiNotifierPapChallengeMsgDialog;
	
	// set srv challenge
	iNotifierDataToUser->iPapChallenge.Copy( *iSrvChallengeUnicode);
	iNotifier.StartNotifierAndGetResponse( 
        iStatus,
        KPapNotifierUid,
        *iNotifierDataPckgToUser,
        *iNotifierDataPckgFromUser );
	
	} // CEapTtlsPapActive::StartPapChallengeMsgDialog()


// ---------------------------------------------------------
// CEapTtlsPapActive::CompletePapChallengeMsgDialog()
// ---------------------------------------------------------
// 
void CEapTtlsPapActive::CompletePapChallengeMsgDialog()
	{
	DEBUG( "CEapTtlsPapActive::CompletePapChallengeMsgDialog()" );

	// display query dialog
	Start( EEapTtlsPapActiveShowPapChallengeReplyQueryDialog );

	} // CEapTtlsPapActive::CompletePapChallengeMsgDialog()


// ---------------------------------------------------------
// CEapTtlsPapActive::StartPapChallengeReplyQueryDialog()
// ---------------------------------------------------------
// 
void CEapTtlsPapActive::StartPapChallengeReplyQueryDialog()
	{
	DEBUG( "CEapTtlsPapActive::StartPapChallengeReplyQueryDialog()" );
	
	if ( iNotifierDataPckgToUser == NULL ||
		 iNotifierDataPckgFromUser == NULL ||
		 iNotifierDataToUser == NULL ||
		 iNotifierDataFromUser == NULL )
        {
		DEBUG( "CEapTtlsPapActive::StartPapChallengeMsgDialog() \
			ERROR: data pointer is NULL." );
		return;
		}

	iNotifierDataToUser->iState = TPapUiNotifierInfo::
	    EPapUiNotifierPapChallengeReplyQueryDialog;

	iNotifier.StartNotifierAndGetResponse( 
	    iStatus,
	    KPapNotifierUid,
	    *iNotifierDataPckgToUser,
		*iNotifierDataPckgFromUser );
	
	} // CEapTtlsPapActive::StartPapChallengeReplyQueryDialog()


// ---------------------------------------------------------
// CEapTtlsPapActive::CompletePapChallengeMsgDialog()
// ---------------------------------------------------------
// 
void CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog()
	{
	DEBUG( "CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog()" );
	
    if ( iStatus == KErrNone )
    	{
    	iUserAction = EPapNotifierUserActionOk;
    	}
    else if ( iStatus == KErrCancel )
		{
		iUserAction = EPapNotifierUserActionCancel;	
		}		
	else
		{
	    DEBUG1( "CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog() \
	        ERROR: iStatus=%d", iStatus.Int() );
		return;
		}
    DEBUG1( "CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog() \
        iUserAction=%d", iStatus.Int() );   
	
	if ( !iCaller )
		{
		DEBUG( "CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog() \
	        ERROR: iCaller==NULL." );
		return;
		}
	if ( !iNotifierDataFromUser )
		{
		DEBUG( "CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog() \
            ERROR: iNotifierDataFromUser==NULL." );		
		return;
		}
	if ( iUserAction == EPapNotifierUserActionOk )
		{
		// update password with user challenge reply
		iTtlsPapDbInfo.iUsrPwdInfo.iPassword = iNotifierDataFromUser->
		    iUsrPwdInfo.iPassword;			
		
        // convert from unicode to utf8
		TBuf8<KMaxPapUserNameLength> userNameUtf8;
    	CnvUtfConverter::ConvertFromUnicodeToUtf8( userNameUtf8,
   			iTtlsPapDbInfo.iUsrPwdInfo.iUserName ); 	
    	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
    		EAPL( "userNameUtf8" ),
    		userNameUtf8.Ptr(),
    		userNameUtf8.Size() ) );

    	TBuf8<KMaxPapPasswordLength> passwordUtf8;
    	CnvUtfConverter::ConvertFromUnicodeToUtf8( passwordUtf8,
    		iNotifierDataFromUser->iUsrPwdInfo.iPassword );   	
    	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
    		EAPL( "passwordUtf8" ),
    		passwordUtf8.Ptr(),
    		passwordUtf8.Size() ) );
   	
    	// complete query with user name and password from UI
    	iCaller->CompleteQueryTtlsPapUserNameAndPassword(
        	eap_status_ok, userNameUtf8, passwordUtf8 );
		}
  	else //if (userAction == EPapNotifierUserActionCancel)
  		{
  		// user name and password are not used
		iCaller->CompleteQueryTtlsPapUserNameAndPassword(
			eap_status_user_cancel_authentication,
			KNullDesC8(),
			KNullDesC8() );
  		} 
	} // CEapTtlsPapActive::CompletePapChallengeReplyQueryDialog()


// ================= private: new, other =======================


// ---------------------------------------------------------
// CEapTtlsPapActive::GetCurrentTime()
// ---------------------------------------------------------
// 
TInt64 CEapTtlsPapActive::GetCurrentTime()
	{
	DEBUG( "CEapTtlsPapActive::GetCurrentTime()" );
	
	TTime currentTime;
	currentTime.UniversalTime();
		
#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT,
	(EAPL("eap_am_type_tls_peap_symbian_c::GetCurrentTime(), %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

#endif

	return currentTime.Int64();
	}

// ---------------------------------------------------------
// CEapTtlsPapActive::Clean()
// ---------------------------------------------------------
// 
void CEapTtlsPapActive::Clean()
	{
    DEBUG( "CEapTtlsPapActive::Clean() IN" );
    
    iCancelCalled = ETrue;

    DEBUG( "CEapTtlsPapActive::Clean() iActiveState set to EEapTtlsPapActiveStatesNumber" );
    iActiveState = EEapTtlsPapActiveStatesNumber;
    
	DEBUG( "CEapFastActive::Clean() close notifier." );
	iNotifier.Close();

    DEBUG( "CEapTtlsPapActive::Clean() delete iNotifierDataToUser." );
    delete iNotifierDataToUser;
    iNotifierDataToUser = NULL;
    
    DEBUG( "CEapTtlsPapActive::Clean() delete iNotifierDataPckgToUser." );
    delete iNotifierDataPckgToUser;	
    iNotifierDataPckgToUser = NULL;
    
    DEBUG( "CEapTtlsPapActive::Clean() delete iNotifierDataFromUser." );
	delete iNotifierDataFromUser;
	iNotifierDataFromUser = NULL;

	DEBUG( "CEapTtlsPapActive::Clean() delete iNotifierDataFromUser." );
	delete iNotifierDataPckgFromUser;
	iNotifierDataPckgFromUser = NULL;
	
    DEBUG( "CEapTtlsPapActive::Clean() OUT." );	
	}

// ================= private: private constructors =======================

// ---------------------------------------------------------
// CEapTtlsPapActive::CEapTtlsPapActive()
// ---------------------------------------------------------
//
CEapTtlsPapActive::CEapTtlsPapActive(
	eap_am_type_tls_peap_symbian_c* aCaller,
	eap_am_tools_symbian_c* aAmTools )
    :
	CActive( CActive::EPriorityStandard ),
    iAmTools( aAmTools ),
	iCaller( aCaller ),
    //iPartner( aPartner ),
    iActiveState( EEapTtlsPapActiveStatesNumber ),
    iNotifier(),
    iNotifierDataToUser( NULL ),
	iNotifierDataPckgToUser( NULL ),	
	iNotifierDataFromUser( NULL ),
	iNotifierDataPckgFromUser( NULL ),
	iUserAction( EPapNotifierUserActionCancel ),
	iSrvChallengeUnicode( NULL ),
	iRequestStatus( NULL ),
	iIsTtlsPapDbInfoInitialized( EFalse ),
	iCancelCalled( EFalse )
    {
    DEBUG( "CEapTtlsPapActive::CEapTtlsPapActive()" );
    }
	
// ---------------------------------------------------------
// CEapTtlsPapActive::ConstructL()
// ---------------------------------------------------------
//
void CEapTtlsPapActive::ConstructL()
    {
	DEBUG( "CEapTtlsPapActive::ConstructL()" );
	CActiveScheduler::Add( this );
	
    DEBUG( "CEapTtlsPapActive::ConstructL() connecting to notifier server");
    TInt err = iNotifier.Connect();
    if ( err != KErrNone )
        {
        DEBUG1( "CEapTtlsPapActive::Start() ERROR: Failed to connect to notifier server, err=%d",
	        err );
        return;
        }
    if ( !iNotifierDataToUser )
    	{
    	iNotifierDataToUser = new(ELeave) TPapUiNotifierInfo;	
    	}
	if ( !iNotifierDataPckgToUser )
		{
		iNotifierDataPckgToUser = new(ELeave) TPckg<TPapUiNotifierInfo> (*iNotifierDataToUser);	
		}
	if ( !iNotifierDataFromUser )
		{
		iNotifierDataFromUser = new(ELeave) TPapUiNotifierInfo;
		}
	if ( !iNotifierDataPckgFromUser )
		{
		iNotifierDataPckgFromUser = new(ELeave) TPckg<TPapUiNotifierInfo> (*iNotifierDataFromUser);			
		}	
    }

// End of File
