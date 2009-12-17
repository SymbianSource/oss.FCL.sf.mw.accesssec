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



#ifndef EAPGTCDBDEFAULTS_H
#define EAPGTCDBDEFAULTS_H

// LOCAL CONSTANTS

_LIT(default_EAP_GTC_identity, "");

const TInt64 default_MaxSessionTime = 0; // 0 means read from configuration file.
const TInt64 default_FullAuthTime = 0;

const TUint KMaxIdentityLengthInDB = 255;

#endif // EAPGTCDBDEFAULTS_H

// End of File
