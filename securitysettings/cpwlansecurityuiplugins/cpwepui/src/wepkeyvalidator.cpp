/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description: 
 *    Validation methods for WEP keys
 *
 */

/*
 * %version: tr1cfwln#5 %
 */

#include <QString>
#include <QDebug>
#include "wepkeyvalidator.h"

/*!
    \class WepKeyValidator wepkeyvalidator.cpp
    \brief Utilities for WEP key validations.
    
*/
/*!
    \enum WepKeyValidator::KeyStatus
    This enum defines the validation results.

    \var WepKeyValidator::KeyStatusOk
    Key is valid.
    
    \var WepKeyValidator::KeyStatusIllegalCharacters
    Key contains illegal characters.

    \var WepKeyValidator::KeyStatusWepInvalidLength
    WEP key length is not valid. Valid keys are 
    - hex: 10 or 26 characters
    - ascii: 5 or 13 characters. See WlanWizardUtils::validateWpaKey().
*/


/*!
 * Process WEP key validation. Following keys are allowed:
 * 
 * HEX: 
 * - 64 bit: allowed key length = 10
 * - 128 bit: allowed key length = 26
 * 
 * ASCII:
 * - 64 bit: allowed key length = 5   
 * - 128 bit: allowed key length = 13
 * 
 * @param key WEP Key to be validated
 * 
 * @return Following values are possible
 * - KeyStatusOk
 * - KeyStatusIllegalCharacters
 * - KeyStatusWepInvalidLength
 */
WepKeyValidator::KeyStatus WepKeyValidator::validateWepKey(const QString &key)
{
    int length = key.length();
    KeyStatus ret = KeyStatusOk;
    // HEX
    if (length == WepHex64BitMaxLength || length == WepHex128BitMaxLength) {
        ret = isHex(key);
    }
    // ASCII
    else if (length == WepAscii64BitMaxLength || length == WepAscii128BitMaxLength) {
        ret = isAscii(key);
    }

    else {
        ret = KeyStatusWepInvalidLength;
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
WepKeyValidator::KeyStatus WepKeyValidator::isAscii(const QString &key)
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
WepKeyValidator::KeyStatus WepKeyValidator::isHex(const QString &key)
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
