/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Panic function and codes.     
*
*/


#ifndef WPASECURITYSETTINGSUIPANIC_H
#define WPASECURITYSETTINGSUIPANIC_H

// TYPES

/**
* Panic reasons for WPA Security Settings UI.
*/
enum TWpaSecuritySettingsPanicCodes
	{
    EUnknownCase,
    ETableNotFound
	};


// FUNCTION DECLARATIONS

/**
* Panic the thread.
* @param aReason Reason for the panic.
*/
void Panic( TWpaSecuritySettingsPanicCodes aPanic );

#endif
