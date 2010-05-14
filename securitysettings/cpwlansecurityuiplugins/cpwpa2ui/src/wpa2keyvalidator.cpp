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
 *   Validate WPA2 only keys
 *
 */
/*
 * %version: 1 %
 */

#include <QString>
#include "wpa2keyvalidator.h"

/*!
    \class Wpa2KeyValidator wpa2keyvalidator.cpp
    \brief Utilities for WPA2 only key validations.
    
*/
/*!
    \enum Wpa2KeyValidator::KeyStatus
    This enum defines the validation results.

    \var Wpa2KeyValidator::KeyStatusOk
    Key is valid.
    
    \var Wpa2KeyValidator::KeyStatusIllegalCharacters
    Key contains illegal characters.
    
    \var Wpa2KeyValidator::KeyStatusWpa2TooShort
    WPA key is too short. Minimum allowed length is 8. See 
    WlanWizardUtils::validateWpaKey().
    
    \var Wpa2KeyValidator::KeyStatusWpa2TooLong
    WPA key is too long. Minimum allowed length is 64 for hex key and 63 for 
    ascii key. See WlanWizardUtils::validateWpaKey().
*/

/*! 
 * Process WPA2 key validation. A passphrase can contain from 8 to 63 ASCII
 * characters where each character MUST have a decimal encoding in the range of
 * 32 to 126, inclusive.
 *
 * A preshared key is stored as 64 character hex string.
 * 
 * @param key PSK to be validated
 * 
 * @return Following values are possible
 * - KeyStatusOk
 * - KeyStatusIllegalCharacters
 * - KeyStatusWpa2TooShort
 * - KeyStatusWpa2TooLong
 */
Wpa2KeyValidator::KeyStatus Wpa2KeyValidator::validateWpa2Key(const QString &key)
{
    int length = key.length();
    KeyStatus ret = KeyStatusOk;

    if (length < Wpa2MinLenght) {
        ret = KeyStatusWpa2TooShort;
    }
    else if (length > Wpa2MaxLenght) {
        ret = KeyStatusWpa2TooLong;
    }
    // hex string
    else if (length == Wpa2MaxLenght) {
        ret = isHex(key);
    }
    else {
        ret = isAscii(key);
    }

    return ret;
}


/*!
 * Process Ascii validation. Allowed characters are from 32 to 126.
 * 
 * @param key to be validated.
 * 
 * @return Following values are possible
 * - KeyStatusOk
 * - KeyStatusIllegalCharacters
 */
Wpa2KeyValidator::KeyStatus Wpa2KeyValidator::isAscii(const QString &key)
{
    QChar ch32(32);
    QChar ch126(126);

    const QChar *data = key.data();
    while (!data->isNull()) {
        if ((*data) < ch32 || (*data) > ch126) {
            return KeyStatusIllegalCharacters;
        }
        ++data;
    }
    return KeyStatusOk;
}

/*!
 * Process Hex validation. Allowed characters are
 * - from 0 to 9
 * - from a to f
 * - from A to F
 * 
 * @param key to be validated.
 * 
 * @return Following values are possible
 * - KeyStatusOk
 * - KeyStatusIllegalCharacters
 */
Wpa2KeyValidator::KeyStatus Wpa2KeyValidator::isHex(const QString &key)
{
    QChar ch_A(65); // Character: A
    QChar ch_F(70); // Character: F
    QChar ch_a(97); // Character: a
    QChar ch_f(102);// Character: f

    const QChar *data = key.data();
    while (!data->isNull()) {
        if (data->isDigit() ||
            (*data) >= ch_a && (*data) <= ch_f ||
            (*data) >= ch_A && (*data) <= ch_F) {
            ++data;
        }
        else {
            return KeyStatusIllegalCharacters;
        }
    }
    return KeyStatusOk;
}
