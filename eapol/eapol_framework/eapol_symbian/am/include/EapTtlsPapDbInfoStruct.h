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

#ifndef EAPTTLSPAPDBINFOSTRUCT_H
#define EAPTTLSPAPDBINFOSTRUCT_H


#include "EapTtlsPapNotifierStruct.h"

/**
* Structure helps to unify read/write TTLS-PAP
* database operations.
*/
struct TTtlsPapDbInfo
    {
	/**
    * Notifier data structure. Contains prompt value,
    * user name and password.
	*/    
	TPapUserNamePasswordInfo iUsrPwdInfo;
	
	/**
	* Maximum cache time for PAP session.
	*/
	TInt64 iMaxSessionTime;
	
	/**
    * Last time when data was updated in cache.
	*/   
	TInt64 iLastFullAuthTime;
	};

#endif // EAPTTLSPAPDBINFOSTRUCT_H

// End of File
