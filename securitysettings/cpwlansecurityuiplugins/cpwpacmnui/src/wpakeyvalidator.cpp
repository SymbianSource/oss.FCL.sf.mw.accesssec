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
 *   Validation methods for WPA/WPA2 & WPA2 only keys
 *
 */

/*
 * %version: tr1cfwln#3 %
 */

//System Includes
#include <QString>

//User Includes
#include "wpakeyvalidator.h"
#include "OstTraceDefinitions.h"

//Trace Definition
#ifdef OST_TRACE_COMPILER_IN_USE
#include "wpakeyvalidatorTraces.h"
#endif

/*!
 \class WpaKeyValidator wpakeyvalidator.cpp
 \brief Utilities for WPA/WPA2 key validations.
 
 */
/*!
 \enum WpaKeyValidator::KeyStatus
 This enum defines the validation results.

 \var WpaKeyValidator::KeyStatusOk
 Key is valid.
 
 \var WpaKeyValidator::KeyStatusIllegalCharacters
 Key contains illegal characters.
 
 \var WpaKeyValidator::KeyStatusWpaTooShort
 WPA key is too short. Minimum allowed length is 8. See 
 WlanWizardUtils::validateWpaKey().
 
 \var WpaKeyValidator::KeyStatusWpaTooLong
 WPA key is too long. Minimum allowed length is 64 for hex key and 63 for 
 ascii key. See WlanWizardUtils::validateWpaKey().
 
 */

/*! 
 * Process WPA key validation. A passphrase can contain from 8 to 63 ASCII
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
 * - KeyStatusWpaTooShort
 * - KeyStatusWpaTooLong
 */
WpaKeyValidator::KeyStatus WpaKeyValidator::validateWpaKey(const QString &key)
{
    OstTraceFunctionEntry0( WPAKEYVALIDATOR_VALIDATEWPAKEY_ENTRY );

    int length = key.length();
    KeyStatus ret = KeyStatusOk;

    if (length < WpaMinLenght) {
        ret = KeyStatusWpaTooShort;
    }
    else if (length > WpaMaxLenght) {
        ret = KeyStatusWpaTooLong;
    }
    // hex string
    else if (length == WpaMaxLenght) {
        ret = isHex(key);
    }
    else {
        ret = isAscii(key);
    }

    OstTraceFunctionExit0( WPAKEYVALIDATOR_VALIDATEWPAKEY_EXIT );
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
WpaKeyValidator::KeyStatus WpaKeyValidator::isAscii(const QString &key)
{
    OstTraceFunctionEntry0( WPAKEYVALIDATOR_ISASCII_ENTRY );

    QChar ch32(32);
    QChar ch126(126);

    const QChar *data = key.data();
    while (!data->isNull()) {
        if ((*data) < ch32 || (*data) > ch126) {

            OstTraceFunctionExit0( WPAKEYVALIDATOR_ISASCII_EXIT );
            return KeyStatusIllegalCharacters;
        }
        ++data;
    }

    OstTraceFunctionExit0( DUP1_WPAKEYVALIDATOR_ISASCII_EXIT );
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
WpaKeyValidator::KeyStatus WpaKeyValidator::isHex(const QString &key)
{
    OstTraceFunctionEntry0( WPAKEYVALIDATOR_ISHEX_ENTRY );

    QChar ch_A(65); // Character: A
    QChar ch_F(70); // Character: F
    QChar ch_a(97); // Character: a
    QChar ch_f(102);// Character: f

    const QChar *data = key.data();
    while (!data->isNull()) {
        if (data->isDigit() || (*data) >= ch_a && (*data) <= ch_f || (*data)
                >= ch_A && (*data) <= ch_F) {
            ++data;
        }
        else {

            OstTraceFunctionExit0( WPAKEYVALIDATOR_ISHEX_EXIT );
            return KeyStatusIllegalCharacters;
        }
    }

    OstTraceFunctionExit0( DUP1_WPAKEYVALIDATOR_ISHEX_EXIT );
    return KeyStatusOk;
}
