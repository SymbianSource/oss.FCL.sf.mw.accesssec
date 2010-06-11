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
 *   EAP method configuration QT interface private implementation
 *
 */

/*
 * %version: 29 %
 */

#ifndef EAPQTCONFIGINTERFACEPRIVATE_H
#define EAPQTCONFIGINTERFACEPRIVATE_H

#include <qglobal.h>
#include <EapSettings.h>
#include <EapTypeDefinitions.h>
#include <eapqtconfig.h>
#include <eapqtpluginhandle.h>
#include <eapqtconfiginterface.h>

/*!
 * @addtogroup group_eap_config_if_impl
 * @{
 */
class HbTranslator;
class CEapType;
class CEapGeneralSettings;
class CpEapPluginInterface;
class EapQtConfigInterface;

class EapQtConfigInterfacePrivate
{
public:

    // maximum lenghts (number of characters) for UTF-16 strings copied to EAP settings
    static const unsigned int StringMaxLength = KGeneralStringMaxLength;
    static const unsigned int CertLabelMaxLength = KMaxCertLabelLength;
    static const unsigned int CertThumbprintMaxLength = KThumbprintMaxLength;
    static const unsigned int CertSubjectKeyIdLength = KSHA1HashLengthBytes;

public:

    // the constructor can only be used for validators
    // any other call trows an exception
    EapQtConfigInterfacePrivate();

    // this is the constructor for using the interface for accessing settings etc.
    // if iapId is negative, it must be later set to correct value with setConfigurationReference
    // to be able to use the methods:
    // - selectedOuterTypes
    // - readConfiguration
    // - saveConfiguration
    // - deleteConfiguration
    // - uiInstance
    // other methods are usable with negative iapId
    EapQtConfigInterfacePrivate(const EapQtConfigInterface::EapBearerType bearerType,
        const int iapId);

    ~EapQtConfigInterfacePrivate();

    QList<EapQtPluginInfo> supportedOuterTypes();
    QList<EapQtPluginInfo> supportedInnerTypes(const EapQtPluginHandle &outerType);

    bool isSupportedOuterType(const EapQtPluginHandle& handle);
    bool isSupportedInnerType(const EapQtPluginHandle& outerHandle,
        const EapQtPluginHandle& innerHandle);

    QList<EapQtCertificateInfo> certificateAuthorityCertificates();
    QList<EapQtCertificateInfo> userCertificates();

    EapQtValidator *validatorEap(EapQtExpandedEapType type, EapQtConfig::SettingsId id);

    CpBaseSettingView *uiInstance(const EapQtPluginHandle& outerHandle,
        const EapQtPluginHandle& pluginHandle);

    // if iapId was negative in the constructor, this method must be called before
    // calling the following methods
    bool setConfigurationReference(const int iapId);

    QList<EapQtPluginHandle> selectedOuterTypes();
    bool setSelectedOuterTypes(const QList<EapQtPluginHandle>& outerHandles);

    bool readConfiguration(const EapQtPluginHandle& outerHandle,
        const EapQtPluginHandle& pluginHandle, EapQtConfig &config);
    bool saveConfiguration(const EapQtPluginHandle& pluginHandle, EapQtConfig &config);

    bool deleteConfiguration();

private:

    void loadPlugins();

    bool fetchCertificates(QList<EapQtCertificateInfo>* const caInfos,
        QList<EapQtCertificateInfo>* const clientInfos);

    void copyCertificateInfo(const RPointerArray<EapCertificateEntry>* const certEntries, QList<
        EapQtCertificateInfo>* const certInfos);

    void appendCertificateInfo(bool isCaCertificate, const EapQtCertificateInfo& certInfo,
        RPointerArray<EapCertificateEntry>* const certList);

    void appendEapTypes(const RArray<TEapExpandedType>* const eapTypes,
        QList<QByteArray>* const eapList);

    void getEapTypeIf(const EapQtPluginHandle& pluginHandle);

    void copyFromEapSettings(EAPSettings& eapSettings, EapQtConfig& config);

    void copyToEapSettings(EapQtConfig& config, EAPSettings& eapSettings);

    TBool convertToTbool(bool value);
    bool convertToBool(TBool value);

    bool isUiSupported(const QByteArray &eapType, int &pluginIndex) const;

    void checkInstanceThrowing() const;

    bool setEapDbIndex(const int iapId);
    bool setEapWlanDbIndex(const int iapId);

    void shutdown();

    EapQtConfigInterface::EapBearerType getEapBearer();

private:

    Q_DISABLE_COPY(EapQtConfigInterfacePrivate)

    const bool mValidatorInstance;

    // list of available EAP UIs
    QList<CpEapPluginInterface*> mPlugins;

    // list of EAPs supported by UI
    QList<EapQtPluginInfo> mPluginInfos;

    // list of supported outer EAP methods,
    // combination of UI and EAP server support
    QList<EapQtPluginInfo> mSupportedOuterTypes;

    // list of supported inner EAP methods queried last time,
    // combination of UI and EAP server support
    QList<EapQtPluginInfo> mSupportedInnerTypes;
    EapQtPluginHandle mLastOuterHandle;

    QScopedPointer<HbTranslator> mTranslator;

private:

    QScopedPointer<CEapGeneralSettings> mEapGsIf;
    QScopedPointer<CEapType> mEapTypeIf;

    int mIapId;
    TIndexType mEapBearer;
    TInt mEapDbIndex;
    bool mEapDbIndexValid;
    TEapExpandedType mCurrentServerEapType;

    // EAP server lists of its supported outer EAP methods
    RArray<TEapExpandedType> mOuterEapsOn;
    RArray<TEapExpandedType> mOuterEapsOff;

};

/*! @} */

#endif

