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
 * %version: 8 %
 */

#ifndef EAPQTCONFIG_H
#define EAPQTCONFIG_H

// System includes
#include <QList>
#include <QVariant>
#include <eapqtconfigexport.h>

// User includes

// Forward declarations
class EapQtConfigPrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtConfig
{

public:

    // Data types

    enum CipherSuite
    {
        /* from RFC4346, listing only suites supported by EAP server */
        TLS_NULL_WITH_NULL_NULL           = 0x0000,
        TLS_RSA_WITH_RC4_128_MD5          = 0x0004,
        TLS_RSA_WITH_RC4_128_SHA          = 0x0005,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA     = 0x000a,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
        TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002f,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033,
        TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,
    };

    enum SettingsId
    {
        // see also EapSettings.h

        /*! bool */
        UsernameAutomatic = 0,
        /*! QString */
        Username,
        /*! bool */
        PasswordPrompt,
        /*! write-only: QString */
        Password,
        /*! bool
         * in read: defines if password already exists in settings database
         * in write: when true, defines that password is not included in the provided
         *      configuration since it already exists in settings database, i.e. earlier
         *      set password remains unchanged */
        PasswordStored,
        /*! write-only: bool
         * true: clears the password from database
         * false: does nothing
         */
        PasswordClear,
        /*! bool */
        RealmAutomatic,
        /*! QString */
        Realm,
        /*! bool */
        UsePseudonyms,
        /*! bool */
        VerifyServerRealm,
        /*! bool */
        ClientAuthenticationRequired,
        /*! uint */
        SessionValidityTime,
        /*! QList<uint>, values from EapQtConfig::CipherSuite */
        CipherSuites,
        /*! bool */
        PeapVersion0Allowed,
        /*! bool */
        PeapVersion1Allowed,
        /*! bool */
        PeapVersion2Allowed,
        /*! bool */
        AuthorityCertificateAutomatic,
        /*! QList< QVariant(EapQtCertificateInfo) > */
        AuthorityCertificate,
        /*! QList< QVariant(EapQtCertificateInfo) > */
        UserCertificate,
        /*! QList< QVariant(EapQtPluginHandle) > */
        InnerType,
        /*!  EapQtPluginHandle */
        OuterType,
        /*! bool */
        ProvisioningModeAuthenticated,
        /*! bool */
        ProvisioningModeUnauthenticated,
        /*! QString */
        PACGroupReference,
        /*! bool */
        WarnADHPNoPAC,
        /*! bool */
        WarnADHPNoMatchingPAC,
        /*! bool */
        WarnNotDefaultServer,
        /*! bool */
        UseIdentityPrivacy,
        /* marker for the last entry */
        SettingsIdLast
    };

    // default constructor
    EapQtConfig();
    // destructor
    ~EapQtConfig();

    // gets the configuration field referred to by an id from SettingsId
    // returns QVariant::Invalid is the field has not been set
    QVariant value(const SettingsId id) const;

    // sets the configuration field referred to by an id from SettingsId
    // does nothing if newValue >= SettingsIdLast
    void setValue(const SettingsId id, const QVariant &newValue) const;

    // resets the object i.e. any successive call to
    // value() returns QVariant::Invalid
    void clear() const;

private:

    Q_DISABLE_COPY(EapQtConfig)

private: // data

    QScopedPointer<EapQtConfigPrivate> d_ptr;

};

#endif // EAPQTCONFIG_H
