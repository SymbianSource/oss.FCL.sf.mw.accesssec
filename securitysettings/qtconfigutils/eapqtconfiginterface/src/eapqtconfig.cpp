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
 *   EAP method QT configuration
 *
 */

/*
 * %version: 8 %
 */

#include "eapqtconfig.h"
#include "eapqtconfig_p.h"

//----------------------------------------------------------------------------
//              EapQtConfig                
//----------------------------------------------------------------------------

/*!
 * TODO: check the list
 * 
 * EAP-SIM (TypeEapSim), EAP-AKA (TypeEapAka)
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - UsePseudonyms
 * - SessionValidityTime
 * - Notifications
 * 
 * EAP-GTC (TypeEapGtc), LEAP (TypeLeap), 
 * EAP-MSCHAPv2 (TypeEapMschapv2), Plain MSCHAPv2 (TypePlainMschapv2),
 * PAP (TypePap)
 * - Username
 * - PasswordPrompt
 * - Password
 * - Notifications
 * 
 * EAP-TLS (TypeEapTls)
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - TlsPrivacy
 * - Notifications
 * - CipherSuites
 * 
 * EAP-TTLS (TypeEapTtls)
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - TlsPrivacy
 * - InnerType
 * - Notifications
 * - CipherSuites
 * 
 * EAP-FAST (TypeEapFast)
 * - ProvisioningModeAuthenticated
 * - ProvisioningModeUnAuthenticated
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - ServerNameVerify
 * - ServerName
 * - TlsPrivacy
 * - InnerType
 * - PacStorePassword
 * - PacStoreReset
 * - CipherSuites
 * 
 * PEAP (TypePeap)
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - ServerNameVerify
 * - ServerName
 * - TlsPrivacy
 * - PeapVersion
 * - InnerType
 * - Notifications
 * - CipherSuites
 */
EapQtConfig::EapQtConfig() :
    d_ptr(new EapQtConfigPrivate)
{
}

EapQtConfig::~EapQtConfig()
{
    // scoped pointer deleted automatically
}

QVariant EapQtConfig::value(SettingsId id)
{
    // check for valid range, otherwise memory is consumed for no reason
    if(id >= SettingsIdLast) {
        qDebug("ERROR: EapQtConfig::value - invalid id!");
        return QVariant::Invalid;
    }
    return d_ptr->mSettings[id];
}

void EapQtConfig::setValue(SettingsId id, QVariant newValue)
{
    // check for valid range, otherwise memory is consumed for no reason
    if(id < SettingsIdLast) {
        d_ptr->mSettings[id] = newValue;
    } else {
        qDebug("ERROR: EapQtConfig::setValue - invalid id!");
    }
    return;
}

void EapQtConfig::clear() {
    d_ptr->mSettings.clear();
    return;
}

QList<EapQtConfig::SettingsId> EapQtConfig::validate(
    QList<EapQtConfig::SettingsId> ids)
{
    // TODO: allow validation only for 0 < id < SettingsIdLast
    Q_UNUSED(ids);
    return QList<EapQtConfig::SettingsId>();
}


