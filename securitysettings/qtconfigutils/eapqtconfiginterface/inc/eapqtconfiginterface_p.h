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
 *   EAP method configuration QT interface private implementation
 *
 */

/*
 * %version: 39 %
 */

#ifndef EAPQTCONFIGINTERFACEPRIVATE_H
#define EAPQTCONFIGINTERFACEPRIVATE_H

// System includes
#include <qglobal.h>
#include <EapSettings.h>
#include <EapTypeDefinitions.h>
#include <eapqtconfig.h>
#include <eapqtpluginhandle.h>
#include <eapqtconfiginterface.h>
#include <eapqtpacstoreconfig.h>

// User includes

// Forward declarations
class HbTranslator;
class CEapType;
class CEapGeneralSettings;
class CEapFastPacStore;
class CpEapPluginInterface;
class EapQtConfigInterface;

// External data types

// Constants

// Class declaration
class EapQtConfigInterfacePrivate
{

public:

    // Data types

    // maximum lenghts (number of characters) for UTF-16 strings copied to EAP settings
    static const unsigned int StringMaxLength = KGeneralStringMaxLength;
    static const unsigned int CertLabelMaxLength = KMaxCertLabelLength;
    static const unsigned int CertThumbprintMaxLength = KThumbprintMaxLength;
    static const unsigned int CertSubjectKeyIdLength = KSHA1HashLengthBytes;

    // PAC store password is in 8-bit format in EAP server
    static const unsigned int PacPasswordMaxLength = StringMaxLength/2;

    // see eapqtinterface.h for documentation

    EapQtConfigInterfacePrivate();

    EapQtConfigInterfacePrivate(const EapQtConfigInterface::EapBearerType bearerType,
        const int iapId);

    ~EapQtConfigInterfacePrivate();

    QList<EapQtPluginInfo> supportedOuterTypes();
    QList<EapQtPluginInfo> supportedInnerTypes(const EapQtPluginHandle &outerType);

    bool isSupportedOuterType(const EapQtPluginHandle &handle);
    bool isSupportedInnerType(const EapQtPluginHandle &outerHandle,
        const EapQtPluginHandle &innerHandle);

    QList<EapQtCertificateInfo> certificateAuthorityCertificates();
    QList<EapQtCertificateInfo> userCertificates();
    bool updateCertificates();

    bool setConfigurationReference(const int iapId);

    QList<EapQtPluginHandle> selectedOuterTypes();
    bool setSelectedOuterTypes(const QList<EapQtPluginHandle> &outerHandles);

    bool readConfiguration(const EapQtPluginHandle &outerHandle,
        const EapQtPluginHandle &pluginHandle, EapQtConfig &config);
    bool saveConfiguration(const EapQtPluginHandle &pluginHandle, const EapQtConfig &config);

    bool deleteConfiguration();

    EapQtValidator *validatorEap(const EapQtExpandedEapType &type, const EapQtConfig::SettingsId id);

    CpBaseSettingView *uiInstance(const EapQtPluginHandle &outerHandle,
        const EapQtPluginHandle &pluginHandle);

    bool readPacStoreConfiguration(EapQtPacStoreConfig &config);
    bool savePacStoreConfiguration(const EapQtPacStoreConfig &config);
    EapQtValidator *validatorPacStore(const EapQtPacStoreConfig::PacStoreSettings id);

private:

    // see cpp for documentation

    void loadPlugins();

    bool fetchCertificates(QList<EapQtCertificateInfo>* const caInfos,
        QList<EapQtCertificateInfo>* const clientInfos);

    void copyCertificateInfo(const RPointerArray<EapCertificateEntry>* const certEntries, QList<
        EapQtCertificateInfo>* const certInfos);

    void appendCertificateInfo(bool isCaCertificate, const EapQtCertificateInfo &certInfo,
        RPointerArray<EapCertificateEntry>* const certList);

    void appendEapTypes(const RArray<TEapExpandedType>* const eapTypes,
        QList<QByteArray>* const eapList);

    void getEapTypeIf(const EapQtPluginHandle &pluginHandle);

    void copyFromEapSettings(EAPSettings &eapSettings, EapQtConfig &config);

    void copyToEapSettings(const EapQtConfig &config, EAPSettings &eapSettings);

    TBool convertToTbool(bool value);
    bool convertToBool(TBool value);

    bool isUiSupported(const QByteArray &eapType, int &pluginIndex) const;

    void checkInstanceThrowing() const;

    bool setEapDbIndex(const int iapId);
    bool setEapWlanDbIndex(const int iapId);

    void shutdown();

    EapQtConfigInterface::EapBearerType getEapBearer();

    // comparison mehtod for qSort
    // must be static for using via function pointers
    static bool pluginLessThan(const EapQtPluginInfo &plugin1, const EapQtPluginInfo &plugin2);

    void getPacStoreIf();

    Q_DISABLE_COPY(EapQtConfigInterfacePrivate)

private: // data

    /// QT members

    // is current instance for validators only
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

    // currenly loaded outer EAP type
    EapQtPluginHandle mLastOuterHandle;

    // translator objects for EAP UIs
    QScopedPointer<HbTranslator> mTranslator;
    QScopedPointer<HbTranslator> mEapPromptsTranslator;
    
    // read CA and user certificates
    QList<EapQtCertificateInfo> mCaCertificates;
    QList<EapQtCertificateInfo> mUserCertificates;

    /// Symbian members

    // pointers to EAP server interfaces
    QScopedPointer<CEapGeneralSettings> mEapGsIf;
    QScopedPointer<CEapType> mEapTypeIf;
    QScopedPointer<CEapFastPacStore> mPacStoreIf;

    // current IAP ID
    int mIapId;

    // current bearer
    TIndexType mEapBearer;

    // current EAP database reference to current IAP
    TInt mEapDbIndex;

    // if mEapDbIndex is valid (i.e. current IAP is not
    // EapQtConfigInterface::IapIdUndefined)
    bool mEapDbIndexValid;

    // current loaded EAP server type interface
    TEapExpandedType mCurrentServerEapType;

    // EAP server lists of its supported outer EAP methods
    RArray<TEapExpandedType> mOuterEapsOn;
    RArray<TEapExpandedType> mOuterEapsOff;

};

#endif // EAPQTCONFIGINTERFACEPRIVATE_H
