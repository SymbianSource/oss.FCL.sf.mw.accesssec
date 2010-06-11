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
* %version: %
*/

#ifndef EAPTTLSPAPNOTIFIERSTRUCT_H
#define EAPTTLSPAPNOTIFIERSTRUCT_H

/**
* UID of PAP notifier to display authentication query dialog.
*/ 
const TUid KPapNotifierUid = { 0x200159A9 };

/**
* Maximum PAP challenge length.
*/ 
const TUint KMaxPapChallengeLength = 4096;

/**
* Maximum PAP user name.
*/ 
const TUint KMaxPapUserNameLength = 253;

/**
* Maximum PAP password length.
*/ 
const TUint KMaxPapPasswordLength = 128;

/**
* Data structure defines user name, password and password prompt.
*/ 
struct TPapUserNamePasswordInfo
    {
    /**
    * True if password prompt is enabled, False - otherwise.
    */ 
 	TBool iPasswordPromptEnabled;
 	
    /*
 	* Buffer for user name.
 	*/
 	TBuf16<KMaxPapUserNameLength> iUserName;
 	
 	/**
 	* Buffer for password.
 	*/ 
 	TBuf16<KMaxPapPasswordLength> iPassword;   
    };

/**
* Data structure used in notifier communication.
*/ 
struct TPapUiNotifierInfo
    {
    enum TPapUiNotifierState
        {
        EPapUiNotifierAuthQueryDialog,               /* 0 */
        EPapUiNotifierPapChallengeSize,              /* 1 */
        EPapUiNotifierPapChallengeMsgDialog,         /* 2 */
        EPapUiNotifierPapChallengeReplyQueryDialog,  /* 3 */
        // ...
        EPapUiNotifierStatesNumber                   /* 4 */ // keep always as last element
        };

    /**
    * State defines UI notifier logic.
    */ 
    TPapUiNotifierState iState;

    /**
    * Data structure defines user name, password and password prompt.
    */  
    TPapUserNamePasswordInfo iUsrPwdInfo;
    	
	/**
	* PAP challenge message.
	*/
	TUint iSrvChallengeSize;
	TBuf16<KMaxPapChallengeLength> iPapChallenge;
    };

/**
* Defines user action: accepting or cancelling
* authentication query dialog.
*/ 
enum EPapNotifierUserAction
    {
    EPapNotifierUserActionOk,
    EPapNotifierUserActionCancel
    };
    
#endif // EAPTTLSPAPNOTIFIERSTRUCT_H

// End of File
