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
* Description: Definitions. 
*
*/


#ifndef WEPSECURITYSETTINGSDEFS_H
#define WEPSECURITYSETTINGSDEFS_H


// CONSTANTS

// Empty key
LOCAL_D const TUint KKeyDataLengthEmpty = 0;

// Number of characters for a 40 bits key
LOCAL_D const TUint KKeyDataLength40Bits  = 10;

// Number of characters for a 104 bits key
LOCAL_D const TUint KKeyDataLength104Bits = 26;

// Number of characters for a 232 bits key
LOCAL_D const TUint KKeyDataLength232Bits = 58;

// The maximum length of key data
LOCAL_D const TUint KMaxLengthOfKeyData = KKeyDataLength232Bits;
                                            
// Number of keys
LOCAL_D const TUint KMaxNumberofKeys = 4;

// Invalid id
LOCAL_D const TUint32 KUidNone = 0;


// UID of application containing help texts (General Settings).
LOCAL_D const TUid KWEPSecuritySettingsUiHelpMajor = { 0x100058EC };

// Error code for invalid length of key data
LOCAL_D const TInt KErrInvalidLength = 101;

// Error code for key data containing invalid characters
LOCAL_D const TInt KErrInvalidChar = 102;


#endif  // WEPSECURITYSETTINGSDEFS_H
