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
 *   EAP method QT configuration
 *
 */

/*
 * %version: 13 %
 */

// System includes
#include <eapqtconfig.h>

// User includes
#include "eapqtconfig_p.h"

/*!
 *  \class EapQtConfig
 *  \brief Public implementation of EAP method QT configuration data
 *         structure for EAP QT configuration interface
 *
 * Following lists the applicable settings per EAP method:
 * 
 * EAP-SIM, EAP-AKA
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - UsePseudonyms
 * - SessionValidityTime
 * - OuterType
 * 
 * EAP-GTC, LEAP, EAP-MSCHAPv2, Plain-MSCHAPv2, PAP
 * - Username
 * - PasswordPrompt
 * - Password
 * - PasswordStored
 * - PasswordClear
 * - SessionValidityTime
 * - OuterType
 * 
 * EAP-TLS
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - VerifyServerRealm
 * - ClientAuthenticationRequired
 * - SessionValidityTime
 * - CipherSuites
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - OuterType
 * - UseIdentityPrivacy
 *
 * EAP-TTLS
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - VerifyServerRealm
 * - ClientAuthenticationRequired
 * - SessionValidityTime
 * - CipherSuites
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - InnerType
 * - UseIdentityPrivacy
 * 
 * EAP-FAST
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - VerifyServerRealm
 * - ClientAuthenticationRequired
 * - SessionValidityTime
 * - CipherSuites
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - InnerType
 * - ProvisioningModeAuthenticated
 * - ProvisioningModeUnauthenticated
 * - PACGroupReference
 * - WarnADHPNoPAC
 * - WarnADHPNoMatchingPAC
 * - WarnNotDefaultServer
 * - UseIdentityPrivacy
 * 
 * PEAP
 * - UsernameAutomatic
 * - Username
 * - RealmAutomatic
 * - Realm
 * - VerifyServerRealm
 * - ClientAuthenticationRequired
 * - SessionValidityTime
 * - CipherSuites
 * - PeapVersion0Allowed
 * - PeapVersion1Allowed
 * - PeapVersion2Allowed
 * - AuthorityCertificateAutomatic
 * - AuthorityCertificate
 * - UserCertificate
 * - InnerType
 * - UseIdentityPrivacy
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtConfig::EapQtConfig() :
    d_ptr(new EapQtConfigPrivate)
{
}

EapQtConfig::~EapQtConfig()
{
    // scoped pointer deleted automatically
}

QVariant EapQtConfig::value(const SettingsId id) const
{
    // check for valid range, otherwise memory is consumed for no reason
    if (id >= SettingsIdLast) {
        qDebug("ERROR: EapQtConfig::value - invalid id!");
        return QVariant::Invalid;
    }
    return d_ptr->mSettings[id];
}

void EapQtConfig::setValue(const SettingsId id, const QVariant &newValue) const
{
    // check for valid range, otherwise memory is consumed for no reason
    if (id < SettingsIdLast) {
        d_ptr->mSettings[id] = newValue;
    }
    else {
        qDebug("ERROR: EapQtConfig::setValue - invalid id!");
    }
}

void EapQtConfig::clear() const
{
    d_ptr->mSettings.clear();
}
