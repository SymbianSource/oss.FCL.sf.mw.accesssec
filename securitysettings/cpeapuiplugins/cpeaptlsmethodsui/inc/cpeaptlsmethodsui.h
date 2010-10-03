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
 *   Control Panel QT UI for TLS-based EAP methods configuration
 *
 */

/*
 * %version: 26 %
 */

#ifndef CPEAPTLSMETHODSUI_H
#define CPEAPTLSMETHODSUI_H

// System includes
#include <cpbasesettingview.h>
#include <eapqtconfiginterface.h>
#include <eapqtplugininfo.h>
#include <eapqtpluginhandle.h>
#include <cpeappacstoreui.h>

// User includes

// Forward declarations
class HbDataForm;
class HbDataFormModel;
class HbDataFormModelItem;
class HbMessageBox;
class HbInputDialog;
class CpSettingFormItemData;
class EapQtValidator;
class EapQtCertificateInfo;
class CpEapCiphersuiteUi;
class EapInnerMethodEntryItemData;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_eap_tlsmethods
 * @{
 */
// Class declaration
class CpEapTlsMethodsUi : public CpBaseSettingView
{
Q_OBJECT

public:
    CpEapTlsMethodsUi(
        const EapQtConfigInterface::EapBearerType bearer,
        const int iapId,
        const EapQtPluginInfo &plugin,
        const EapQtPluginHandle& outerHandle);
    ~CpEapTlsMethodsUi();

    CpBaseSettingView *innerUiInstance();
    CpBaseSettingView *secondInnerUiInstance();

signals:

public slots:

protected:
    void close();

protected slots:

private:
    // Supported PEAP versions
    enum PeapVersions {
        //PEAPv0
        PeapVersion0,
        //PEAPv1
        PeapVersion1,
        //PEAPv0 or PEAPv1
        PeapVersionBoth
    };
    
    enum TlsPrivacyIndexes {
        TlsPrivacyOff,
        TlsPrivacyOn
    };

private:
    void createUi();
    void createTlsUi();
    void createTtlsUi();
    void createPeapUi();
    void createFastUi();
    
    void createUsername();
    void createRealm();
    void createUserCerts();
    void createAuthorityCerts();
    void createPeapVersion();
    void createProvisioning();
    void createTlsPrivacy();
    void createInnerMethod();
    void createEapSelector();
    void createSecondInnerMethod();
    void createSecondEapSelector();
    void createPacStoreGroup();
    
    void defaultInnerPlugin();
    
    bool checkStateToBool(const int state);
    int boolToCheckState(const bool state);
    
    bool validate();
    bool validateUsernameGroup();
    bool validateRealmGroup();
    bool validateAuthorityCertificate();
    bool validateUserCertificate();
    bool validateCiphersuites();
    void setPeapVersion(EapQtConfig &eapConfig);
    void setFastSettings(EapQtConfig &eapConfig);
    bool storeSettings();
    
private slots:  
    void setValidator(const QModelIndex);
    void usernameAutomaticChanged(int state);
    void realmAutomaticChanged(int state);
    void userCertChanged(int value);
    void authorityCertAutomaticChanged(int state);
    void authorityCertChanged(int value);
    void peapVersionChanged(int value);
    void provisioningModeChanged(int state);
    void innerEapTypeChanged(int value);
    void secondInnerEapTypeChanged(int value);
    void incompletedSettingsConfirmed(int action);
    void unableToSaveSettingsClosed(int action);
    
private:
    //! Pointer to EapQtConfigInterface
    QScopedPointer <EapQtConfigInterface> mConfigIf;
    //! List of supported Inner EAP types
    QList<EapQtPluginInfo> mPlugins;
    //! Plugin info
    EapQtPluginInfo mPluginInfo;
    //! Outer handle
    EapQtPluginHandle mOuterHandle;
    //! Current EAP configuration
    EapQtConfig mEapConfig;
    //! Pointer to PAC store UI class
    CpEapPacStoreUi *mPacStoreUi;
    
    //! Dataform
    HbDataForm *mForm;
    //! Datform model
    HbDataFormModel *mModel;
    //! Control Panel item data helper for TLS methods plugins
    CpItemDataHelper *mItemDataHelper;
    //! TLS based methods settings group
    HbDataFormModelItem *mGroupItem;    
    //! Username generate automatically checkBox
    CpSettingFormItemData *mUsernameAutomatic;
    //! Username lineEdit
    CpSettingFormItemData *mUsername;
    //! Realm generate automatically checkBox
    CpSettingFormItemData *mRealmAutomatic;
    //! Realm lineEdit
    CpSettingFormItemData *mRealm;
    //! User certificate comboBox
    CpSettingFormItemData *mUserCertificate;
    //! Authority certificate select automatically checkBox
    CpSettingFormItemData *mCaCertAutomatic;
    //! Authority certificate comboBox
    CpSettingFormItemData *mCaCert;
    //! Peap version comboBox
    CpSettingFormItemData *mPeapVersion;
    //! Authenticated provisioning checkBox
    CpSettingFormItemData *mAuthProvisioning;
    //! Unauthenticated provisioning checkBox
    CpSettingFormItemData *mUnauthProvisioning;
    //! TLS Privacy comboBox
    CpSettingFormItemData *mTlsPrivacy;
    //! Inner EAP type comboBox
    CpSettingFormItemData *mInnerEapType;
    //! Second inner EAP type comboBox
    CpSettingFormItemData *mSecondInnerEapType;
    //! Second inner EAP type configure button
    EapInnerMethodEntryItemData *mSecondEapEntry;
    //! Pac store group
    HbDataFormModelItem *mGroupItemPacStore;
    //! Cipher suites group
    CpEapCiphersuiteUi *mGroupItemCs;
    
    //! Realm validator
    QScopedPointer<EapQtValidator> mValidatorRealm;
    //! Username validator
    QScopedPointer<EapQtValidator> mValidatorUsername;
    
    //! List of system's user certificates
    QList<EapQtCertificateInfo> mUserCerts;
    //! Index of selected user certificate
    int mCurrentUserCert;
    //! List if system's authority certificates
    QList<EapQtCertificateInfo> mAuthorityCerts;
    //! Index of selected authority certificate
    int mCurrentAuthorityCert;
    //! Index of current PEAP version 
    //  0:PEAPv0, 1:PEAPv2, 2:PEAPv0 or PEAPv1
    int mCurrentPeapVersion;
    //! Index of selected Inner EAP type
    int mCurrentInnerPlugin;
    //! Index of selected second Inner EAP type
    int mCurrentSecondInnerPlugin;
    //! Index of inner type EAP-MSCHAPv2, default value for PEAP and EAP-FAST 
    int mInnerEapMschapv2;
    //! Index of inner type EAP-GTC, default value for PEAPv1
    int mInnerEapGtc;
    //! Index of second inner type EAP-GTC
    int mSecondInnerEapGtc;
    //! Tells if no inner EAP type is stored and default value is used instead
    bool mDefaultPluginInUse;
    //! Tells if EAP-MSCHAPv2 is the only possible inner EAP type
    bool mInnerEapMschapv2Only;
    //! List of supported inner EAP types localisation strings
    QStringList mInnerEapItems;
    //! EAP-MSCHAPv2 localisation string. 
    //  Used in Inner EAP tyupe combobox when only EAP-MSCHAPv2 is supported
    QStringList mMschapv2Items;
};

/*! @} */

#endif
