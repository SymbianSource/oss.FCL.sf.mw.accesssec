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

#ifndef WPAKEYVALIDATOR_H
#define WPAKEYVALIDATOR_H

/*!
 * @addtogroup group_wpa_key_validator
 * @{
 */

class WpaKeyValidator
{
public:
    enum KeyStatus
    {
        KeyStatusOk,
        KeyStatusIllegalCharacters,
        KeyStatusWpaTooShort,
        KeyStatusWpaTooLong
    };

    static const int WpaMaxLenght = 64;
    static const int WpaMinLenght = 8;
    
public:

    static KeyStatus validateWpaKey(const QString &key);
    static KeyStatus isAscii(const QString &key);
    static KeyStatus isHex(const QString &key);
};

/*! @} */

#endif /* WPAKEYVALIDATOR_H */
