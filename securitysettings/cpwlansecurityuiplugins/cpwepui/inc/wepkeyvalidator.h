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
 *   Validation methods for WEP keys
 *
 */

/*
 * %version: tr1cfwln#4 %
 */

#ifndef WEPKEYVALIDATOR_H
#define WEPKEYVALIDATOR_H

/*!
 * @addtogroup group_wep_key_validator
 * @{
 */

class WepKeyValidator
{
public:
    enum KeyStatus
    {
        KeyStatusOk,
        KeyStatusIllegalCharacters,
        KeyStatusWepInvalidLength,
    };


    static const int WepHex64BitMaxLength = 10;
    static const int WepHex128BitMaxLength = 26;
    static const int WepAscii64BitMaxLength = 5;
    static const int WepAscii128BitMaxLength = 13;
    static const int WepKeyEmptyString = 0;
    
public:
    static KeyStatus validateWepKey(const QString &key);
    static KeyStatus isAscii(const QString &key);
    static KeyStatus isHex(const QString &key);
};

/*! @} */

#endif /* WEPKEYVALIDATOR_H */
