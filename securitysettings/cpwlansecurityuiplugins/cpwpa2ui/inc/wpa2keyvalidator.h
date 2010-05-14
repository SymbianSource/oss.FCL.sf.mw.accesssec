/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
 * Description: 
 *   WLAN Wizard Utilities
 *
 */

/*
 * %version: 1 %
 */

#ifndef WPA2KEYVALIDATOR_H
#define WPA2KEYVALIDATOR_H

/*!
 * @addtogroup group_wpa_key_validator
 * @{
 */

class Wpa2KeyValidator
{
public:
    enum KeyStatus
    {
        KeyStatusOk,
        KeyStatusIllegalCharacters,
        KeyStatusWpa2TooShort,
        KeyStatusWpa2TooLong,
    };

    static const int Wpa2MaxLenght = 64;
    static const int Wpa2MinLenght = 8;
    
public:

    static KeyStatus validateWpa2Key(const QString &key);
    static KeyStatus isAscii(const QString &key);
    static KeyStatus isHex(const QString &key);
};

/*! @} */

#endif /* WPA2KEYVALIDATOR_H */
