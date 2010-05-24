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
 * %version: 1 %
 */

#ifndef EAPQTCONFIG_H
#define EAPQTCONFIG_H

#include <QList>
#include <QVariant>

#ifdef BUILD_EAP_QT_CONFIG_INTERFACE_DLL
#define EAP_QT_CONFIG_EXPORT Q_DECL_EXPORT
#else
#define EAP_QT_CONFIG_EXPORT Q_DECL_IMPORT
#endif

class EapQtConfigPrivate;

class EAP_QT_CONFIG_EXPORT EapQtConfig
{
public:

    // TODO: document default values

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
         * QList<uint> contains RFC numbers for activated ciphersuites
         *
         * Refer to RFC2246 chapter A.5 for the values.
         *
         * Supported CipherSuites by EAP Server default implementation: 
         * TLS_NULL_WITH_NULL_NULL = (0x0000), 
         * - No key exchange, no encryption and no authentication.
         * TLS_RSA_WITH_RC4_128_MD5 = (0x0004),
         * - RSA key exchange, RC4_128 encryption and MD5 authentication.
         *   NOTE this is included only because PEAP requires this cipher 
         *   suite as a mandatory. Think carefully whether this meets your 
         *   security requirements.
         * TLS_RSA_WITH_RC4_128_SHA = (0x0005), 
         * - RSA key exchange, RC4_128 encryption and SHA1 authentication.
         *   NOTE this is included only because PEAP requires this cipher 
         *   suite as a mandatory. Think carefully whether this meets your 
         *   security
         *   requirements.
         * TLS_RSA_WITH_3DES_EDE_CBC_SHA = (0x000a)
         * - RSA key exchange, 3DES-EDE-CBC encryption and SHA1 
         *   authentication.
         * TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = (0x0016)
         * - Diffie-Helmann RSA key exchange, 3DES-EDE-CBC encryption and SHA1
         *   authentication.
         * TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = (0x0013)
         * - Diffie-Helmann DSS key exchange, 3DES-EDE-CBC encryption and SHA1
         *   authentication.
         * TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F
         * - RSA key exchange, AES-128 encryption and SHA1 authentication.
         * TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032
         * - Diffie-Helmann DSS key exchange, AES-128-CBC encryption and SHA1
         *   authentication.
         * TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033
         * - Diffie-Helmann RSA key exchange, AES-128-CBC encryption and SHA1
         *   authentication.
         * TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,
         * - Supported when EAP-FAST is supported 
         * - Diffie-Helmann anonymous key exchange, AES-128-CBC encryption and 
         *   SHA1 authentication.
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
