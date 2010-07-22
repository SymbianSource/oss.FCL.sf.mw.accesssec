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
 *   Constant definitions for EAP control panel UIs
 *
 */

/*
 * %version: 7 %
 */

#ifndef EAPUIDEFS_H
#define EAPUIDEFS_H

#include <QString>

namespace EapQtUiConstants
{

    // EAP plugin names
    static const QString StringEapAka       = "EAP-AKA";
    static const QString StringEapFast      = "EAP-FAST";
    static const QString StringEapGtc       = "EAP-GTC";
    static const QString StringEapMschapv2  = "EAP-MSCHAPv2";
    static const QString StringEapSim       = "EAP-SIM";
    static const QString StringEapTls       = "EAP-TLS";
    static const QString StringEapTtls      = "EAP-TTLS";
    static const QString StringLeap         = "LEAP";
    static const QString StringMschapv2     = "MSCHAPv2";
    static const QString StringPap          = "PAP";
    static const QString StringPeap         = "PEAP";

    // EAP plugin preference order, i.e. the order in which the plugins
    // are shown on the UI relative to each other
    static const int OrderPeap          = 10;   // outer only
    static const int OrderEapTtls       = 20;   // outer only
    static const int OrderMschapv2      = 30;   // inner only
    static const int OrderPap           = 40;   // inner only
    static const int OrderEapGtc        = 50;   // inner only
    static const int OrderEapMschapv2   = 60;   // inner only
    static const int OrderEapTls        = 70;   // inner & outer
    static const int OrderEapFast       = 80;   // outer only
    static const int OrderLeap          = 90;   // outer only
    static const int OrderEapAka        = 100;  // inner & outer
    static const int OrderEapSim        = 110;  // inner & outer

    // TLS cipher names
    static const QString EapCipher_RSA_AES_SHA      = "RSA, AES, SHA";
    static const QString EapCipher_DHE_RSA_AES_SHA  = "DHE-RSA, AES, SHA";
    static const QString EapCipher_DHE_DSS_AES_SHA  = "DHE-DSS, AES, SHA";
    static const QString EapCipher_RSA_3DES_SHA     = "RSA, 3DES, SHA";
    static const QString EapCipher_DHE_RSA_3DES_SHA = "DHE-RSA, 3DES, SHA";
    static const QString EapCipher_DHE_DSS_3DES_SHA = "DHE-DSS, 3DES, SHA";
    static const QString EapCipher_RSA_RC4_MD5      = "RSA, RC4, MD5";
    static const QString EapCipher_RSA_RC4_SHA      = "RSA, RC4, SHA";

}

#endif // EAPUIDEFS_H
