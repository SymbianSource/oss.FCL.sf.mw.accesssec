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
 * %version: 3 %
 */

#ifndef EAPQTCONFIG_H
#define EAPQTCONFIG_H

#include <QList>
#include <QVariant>
#include <eapqtconfigdefs.h>

class EapQtConfigPrivate;

class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtConfig
{
public:

    enum SettingsId
    {
        // see also EapSettings.h

        /*! bool */
        UsernameAutomatic,
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
        /*! 
         * QList<uint> contains RFC2246 numbers for activated ciphersuites
         *
         * TLS_NULL_WITH_NULL_NULL           = 0x0000 
         * TLS_RSA_WITH_RC4_128_MD5          = 0x0004
         * TLS_RSA_WITH_RC4_128_SHA          = 0x0005 
         * TLS_RSA_WITH_3DES_EDE_CBC_SHA     = 0x000a
         * TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
         * TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
         * TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F
         * TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032
         * TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033
         * TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034
         */
        CipherSuites,
        /*! bool */
        PeapVersion0Allowed,
        /*! bool */
        PeapVersion1Allowed,
        /*! bool */
        PeapVersion2Allowed,
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
        /*! bool */
        AuthorityCertificateAutomatic,
        /*! marker for the last entry */
        SettingsIdLast
    };

public:
    EapQtConfig();
    ~EapQtConfig();

    QVariant value(SettingsId id);
    void setValue(SettingsId id, QVariant newValue);
    QList<EapQtConfig::SettingsId> validate(
        QList<EapQtConfig::SettingsId> ids);
    void clear();

private:
    Q_DISABLE_COPY(EapQtConfig)
    QScopedPointer<EapQtConfigPrivate> d_ptr;
};

#endif
