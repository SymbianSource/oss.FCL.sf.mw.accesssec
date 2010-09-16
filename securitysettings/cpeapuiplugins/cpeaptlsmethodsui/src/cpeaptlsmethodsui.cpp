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
 * %version: 38 %
 */

// System includes
#include <HbDataForm>
#include <HbDataFormModel>
#include <HbDataFormViewItem>
#include <HbParameterLengthLimiter>
#include <HbMessageBox>
#include <HbInputDialog>
#include <HbAction>
#include <HbLineEdit>
#include <cpsettingformitemdata.h>
#include <cpitemdatahelper.h>
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtcertificateinfo.h>
#include <eapqtpacstoreconfig.h>
#include <cppluginutility.h>

// User includes
#include "cpeapciphersuiteui.h"
#include "cpeaptlsmethodsui.h"
#include "cpeappacstoreui.h"
#include "cpeaptlsmethodsinnereapui.h"

/*!
 * \class CpEapTlsMethodsUi
 * \brief Implementes TLS based methods configuration ui. 
 */

// External function prototypes

// Local constants

/*!
 * ComboBox index is unkown
 */
static const int UnknownIndex = -1;
/*!
 * Default index for ComboBox, used if no value has been stored
 */
static const int DefaultIndex = 0;
/*!
 * Index of 'Not in use'in certificate selection lists.
 */
static const int NotInUseIndex = 0;
/*!
 * First item of the list
 */
static const int FirstItem = 0;
/*
 * Second item of the list
 */
static const int SecondItem = 1;
/*!
 * Shift by reason of 'Not in use'
 */
static const int NotInUseShift = 1;

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in] bearer        Bearer type of the accessed configuration.
 * @param [in] iapId         IAP ID of the accessed configuration.
 * @param [in] plugin        Plugin.
 * @param [in] outerHandle   Outer handle.
 */

CpEapTlsMethodsUi::CpEapTlsMethodsUi(
    const EapQtConfigInterface::EapBearerType bearer,
    const int iapId,
    const EapQtPluginInfo &plugin,
    const EapQtPluginHandle& outerHandle) :
        mConfigIf(NULL),
        mPluginInfo(plugin),
        mOuterHandle(outerHandle),
        mForm(NULL),
        mModel(NULL),
        mItemDataHelper(NULL),
        mGroupItem(NULL),
        mUsernameAutomatic(NULL),
        mUsername(NULL),
        mRealmAutomatic(NULL),
        mRealm(NULL),
        mUserCertificate(NULL),
        mCaCertAutomatic(NULL),
        mCaCert(NULL),
        mPeapVersion(NULL),
        mAuthProvisioning(NULL),
        mUnauthProvisioning(NULL),
        mTlsPrivacy(NULL),
        mInnerEapType(NULL),
        mSecondInnerEapType(NULL),
        mSecondEapEntry(NULL),
        mGroupItemPacStore(NULL),
        mGroupItemCs(NULL),
        mCurrentUserCert(0),
        mCurrentAuthorityCert(0),
        mCurrentPeapVersion(0),
        mCurrentInnerPlugin(0),
        mCurrentSecondInnerPlugin(0),
        mInnerEapMschapv2(-1),
        mInnerEapGtc(-1),
        mSecondInnerEapGtc(0),
        mDefaultPluginInUse(false),
        mInnerEapMschapv2Only(false)
{
    qDebug("CpEapTlsMethodsUi::CpEapTlsMethodsUi()");

    // IAP must be valid in construction (check includes
    // EapQtConfigInterface::IapIdUndefined)
    if (iapId < 0) {
        QT_THROW(std::bad_alloc());
        // scoped pointer gets deleted automaticaly on exception
    }
    setObjectName("CpEapTlsMethodsUi");

    // Get EAP config interface
    mConfigIf.reset(new EapQtConfigInterface(bearer, iapId));
    
    // Request supported inner EAP types
    mPlugins.append(mConfigIf->supportedInnerTypes(mPluginInfo.pluginHandle()));

    // Create UI
    createUi();
}

/*!
 * Destructor.
 */
CpEapTlsMethodsUi::~CpEapTlsMethodsUi()
{
    qDebug("CpEapTlsMethodsUi::~CpEapTlsMethodsUi()");
    
    // mEapQtConfigInterface: scoped pointer deleted automatically
    // mValidatorRealm: scoped pointer deleted automatically
    // mValidatorUsername: scoped pointer deleted automatically
}

/*!
 * Calls inner UI instance
 * 
 * @return pointer to inner UI instance
 */
CpBaseSettingView *CpEapTlsMethodsUi::innerUiInstance()
{
    if (mInnerEapMschapv2Only) {
        // Only EAP-MSCHAPv2 in Inner EAP type list
        return mConfigIf->uiInstance(mPluginInfo.pluginHandle(),
            mPlugins.at(mInnerEapMschapv2).pluginHandle());       
    } else {
        return mConfigIf->uiInstance(mPluginInfo.pluginHandle(),
            mPlugins.at(mCurrentInnerPlugin).pluginHandle());        
    }
}

/*!
 * Calls inner UI instance
 * 
 * @return pointer to inner UI instance
 */
CpBaseSettingView *CpEapTlsMethodsUi::secondInnerUiInstance()
{
    // Second inner EAP type can be only EAP-GTC
    Q_ASSERT(mCurrentSecondInnerPlugin == mSecondInnerEapGtc);
    return mConfigIf->uiInstance(mPluginInfo.pluginHandle(),
        mPlugins.at(mInnerEapGtc).pluginHandle());
}

/*!
 * Creates TLS based methods UI and initilizes settings read via
 * EapQtConfigInterface
 */
void CpEapTlsMethodsUi::createUi()
{
    qDebug("CpEapTlsMethodsUi::createUi()");

    // Read EAP Configurations
    bool configurationRead = mConfigIf->readConfiguration(mOuterHandle, mPluginInfo.pluginHandle(),
        mEapConfig);
    if (!configurationRead) {
        qDebug("CpEapTlsMethodsUi::createUi - read configuration failed.");
    }
    
    // Construct TLS based methods settings UI
    mForm = new HbDataForm();
    mForm->setObjectName("CpEapTlsMethodsUiForm");
    this->setWidget(mForm);
    
    CpPluginUtility::addCpItemPrototype(mForm);
    
    mModel = new HbDataFormModel(mForm);
    mModel->setObjectName("CpEapTlsMethodsUiModel");
    
    // Create settings group
    mGroupItem = new HbDataFormModelItem(
        HbDataFormModelItem::GroupItem,
        HbParameterLengthLimiter(
            "txt_occ_subhead_eap_module_settings").arg(
                mPluginInfo.localizationId()));
    
    mGroupItem->setContentWidgetData("objectName", "CpEapTlsMethodsUiGroupItem");
    mModel->appendDataFormItem(mGroupItem);

    // The parameter given as 0 is a HbDataForm pointer, not parent
    mItemDataHelper = new CpItemDataHelper(0);
    mItemDataHelper->setParent(this);

    // Create method specific UI
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapTls) {
        createTlsUi();
    } else if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapTtls) {
        createTtlsUi();
    } else if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginPeap) {
        createPeapUi();
    } else if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapFast) {
        createFastUi();
    } else {
        qDebug("CpEapTlsMethodsUi::createUi() - unknown EAP method");
    }
    
    // Load cipher suites view
    QVariant variant;
    variant = mEapConfig.value(EapQtConfig::CipherSuites);
    mGroupItemCs = new CpEapCiphersuiteUi(variant);
    mModel->appendDataFormItem(mGroupItemCs);

    mItemDataHelper->bindToForm(mForm);
    mForm->setModel(mModel);

    // Connect signal to add validators
    bool connected = connect(
        mForm, 
        SIGNAL( itemShown(const QModelIndex&) ), 
        this,
        SLOT( setValidator(const QModelIndex) ));
    Q_ASSERT(connected); 
    
    // Expand TLS based method settings group
    mForm->setExpanded(mModel->indexFromItem(mGroupItem), true);
    
    // If EAP-FAST expand also PAC store group
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapFast) {
        mForm->setExpanded(mModel->indexFromItem(mGroupItemPacStore), true);    
    }
}

/*!
 * Creates EAP-TLS settings UI
 */
void CpEapTlsMethodsUi::createTlsUi()
{
    qDebug("CpEapTlsMethodsUi::createTlsUi()");
    // Create common TLS settings componenets
    createAuthorityCerts();
    createUserCerts();
    createUsername();
    createRealm();
}

/*!
 * Creates EAP-TTLS settings UI
 */
void CpEapTlsMethodsUi::createTtlsUi()
{
    qDebug("CpEapTlsMethodsUi::createTtlsUi()");
    // Create common TLS settings componenets
    createAuthorityCerts();
    createUserCerts();
    createUsername();
    createRealm();
    
    // Create Inner Eap type selection comboBox and configuration button
    createInnerMethod();
}

/*!
 * Creates PEAP settings UI
 */
void CpEapTlsMethodsUi::createPeapUi()
{
    qDebug("CpEapTlsMethodsUi::createPeapUi()");
    // Create common TLS settings componenets
    createAuthorityCerts();
    createUserCerts();
    createUsername();
    createRealm();
 
    // Create PEAP version selection comboBox
    createPeapVersion();
    
    // Create Inner Eap type selection comboBox and configuration button    
    createInnerMethod();
    
    // If not stored inner Eap type, set default inner EAP method
    // according PEAP version
    if (mDefaultPluginInUse) {
        defaultInnerPlugin();
    }
}

/*!
 * Creates EAP-FAST settings UI
 */
void CpEapTlsMethodsUi::createFastUi()
{
    qDebug("CpEapTlsMethodsUi::createFastUi()");
    
    // Create provisioning selection
    createProvisioning();
    
    // Create common TLS settings componenets
    createAuthorityCerts();
    createUserCerts();
    createUsername();
    createRealm();
    
    // Create TLS privacy
    createTlsPrivacy();
    
    // Create Inner Eap type selection comboBox and configuration button
    createInnerMethod();
  
    // Create second Inner EAP type
    createSecondInnerMethod();
    
    // Create PAC store group
    createPacStoreGroup();
    
    // Dim fields according the provisioning mode (parameter not used)
    provisioningModeChanged(Qt::Checked);
    // Dim Second inner EAP type configure button if 'Not in use' selected
    secondInnerEapTypeChanged(mCurrentSecondInnerPlugin);
}

/*!
 * Creates Username group:
 * Generate automatically checkBox and username lineEdit
 */
void CpEapTlsMethodsUi::createUsername()
{
    qDebug("CpEapTlsMethodsUi::createUsername()");
    // UsernameAutomatic
    mUsernameAutomatic = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_user_name"));
    mGroupItem->appendChild(mUsernameAutomatic);
    
    mUsernameAutomatic->setContentWidgetData(
        "objectName", 
        "CpEapTlsMethodsUiUsernameAutomatic"); 
    mUsernameAutomatic->setContentWidgetData(
        "text", 
        hbTrId("txt_occ_setlabel_user_name_val_generate_automatica"));
    
    // Initialize the value from EapQtConfig
    // Generate username automatically is selected by default
    mUsernameAutomatic->setContentWidgetData(
        "checkState", 
        boolToCheckState(mEapConfig.value(EapQtConfig::UsernameAutomatic).toBool()));
    
    // Connect signal to disable/enable username when usernameAutomatic changed   
    mForm->addConnection(
        mUsernameAutomatic, 
        SIGNAL(stateChanged(int)), 
        this,
        SLOT(usernameAutomaticChanged(int)));

    //Username
    mUsername = new CpSettingFormItemData(
        HbDataFormModelItem::TextItem, 
        hbTrId("txt_occ_setlabel_user_name"));
    mGroupItem->appendChild(mUsername);    
    mUsername->setContentWidgetData("objectName", "CpEapTlsMethodsUiUsername");
    mUsername->setContentWidgetData("text", mEapConfig.value(EapQtConfig::Username));
    
    // Dim username if usernameAutomatic selected
    usernameAutomaticChanged(mUsernameAutomatic->contentWidgetData("checkState") == Qt::Checked);
}

/*!
 * Creates Realm group:
 * Generate automatically checkBox and realm lineEdit
 */
void CpEapTlsMethodsUi::createRealm()
{
    qDebug("CpEapTlsMethodsUi::createRealm()");
    // RealmAutomatic
    mRealmAutomatic = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_realm"));
    mGroupItem->appendChild(mRealmAutomatic);
    
    mRealmAutomatic->setContentWidgetData("objectName", "CpEapTlsMethodsUiRealmAutomatic");
    mRealmAutomatic->setContentWidgetData(
        "text", 
        hbTrId("txt_occ_setlabel_realm_val_generate_automatically"));
    
    // Initialize the value from EapQtConfig
    // Generate realm automatically is selected by default
    mRealmAutomatic->setContentWidgetData(
        "checkState", 
        boolToCheckState(mEapConfig.value(EapQtConfig::RealmAutomatic).toBool()));
    
    // connect signal to disable/enable realm when realmAutomatic changed 
    mForm->addConnection(
        mRealmAutomatic, 
        SIGNAL(stateChanged(int)), 
        this,
        SLOT(realmAutomaticChanged(int)));

    //Realm
    mRealm = new CpSettingFormItemData(
        HbDataFormModelItem::TextItem, 
        hbTrId("txt_occ_setlabel_realm"));
    mGroupItem->appendChild(mRealm); 
    
    mRealm->setContentWidgetData("objectName", "CpEapTlsMethodsUiRealm");
    mRealm->setContentWidgetData("text", mEapConfig.value(EapQtConfig::Realm));
    
    // Dim realm if realmAutomatic selected
    realmAutomaticChanged(mRealmAutomatic->contentWidgetData("checkState") == Qt::Checked);
}

/*!
 * Creates User certificate selection comboBox
 */
void CpEapTlsMethodsUi::createUserCerts()
{
    qDebug("CpEapTlsMethodsUi::createUserCerts()");
    // Create User certificate comboBox
    mUserCertificate = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_user_certificate"));
    mGroupItem->appendChild(mUserCertificate);
    
    mUserCertificate->setContentWidgetData("objectName", "CpEapTlsMethodsUiUserCertSelector");
    
    // Stored certificate
    QList<QVariant> storedCertsList = mEapConfig.value(EapQtConfig::UserCertificate).toList();
    EapQtCertificateInfo storedCert;
    if (!storedCertsList.empty() && storedCertsList[FirstItem].canConvert<EapQtCertificateInfo> ()) {
        // Stored certificate found, index is still unknown 
        storedCert = storedCertsList[FirstItem].value<EapQtCertificateInfo> ();
        mCurrentUserCert = UnknownIndex;
    } else {
        // no stored certificate, use 'not in use'
        mCurrentUserCert = DefaultIndex;
    }

    // User certificates found from system
    mUserCerts = mConfigIf->userCertificates();
    
    // List of comboBox items
    QStringList items;
    // Add 'Not in use' to comboBox list
    items << hbTrId("txt_occ_setlabel_user_certificate_val_not_in_use");
    // Add certificates to comboBox list and find index of stored certificate
    for (int i = 0; i < mUserCerts.count(); ++i) {
        items << mUserCerts.at(i).value(EapQtCertificateInfo::CertificateLabel).toString();
        if (mCurrentUserCert == UnknownIndex 
            && storedCert.value(EapQtCertificateInfo::SubjectKeyId)
            == mUserCerts.at(i).value(EapQtCertificateInfo::SubjectKeyId)) {
            mCurrentUserCert = i + NotInUseShift;
        }
    }
    if (mCurrentUserCert == UnknownIndex) {
        // Stored certificate not found in the certificate list
        qDebug("CpEapTlsMethodsUi::createUserCerts() - stored certificate not in the list");
        mCurrentUserCert = DefaultIndex;
    }
    
    // Initialize comboBox
    mUserCertificate->setContentWidgetData("items", items);
    mUserCertificate->setContentWidgetData("currentIndex", mCurrentUserCert);
    
    // Get info when user certificate selection has been changed
    mForm->addConnection(mUserCertificate, SIGNAL(currentIndexChanged(int)), this,
        SLOT(userCertChanged(int)));
}

/*!
 * Creates Authority certs group:
 * Select automatically check box and certificate comboBox
 */
void CpEapTlsMethodsUi::createAuthorityCerts()
{
    qDebug("CpEapTlsMethodsUi::createAuthorityCerts()");
    // Select Authority Certificate Automatically
    mCaCertAutomatic = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_authority_certificate"));
    mGroupItem->appendChild(mCaCertAutomatic);
    
    mCaCertAutomatic->setContentWidgetData("objectName", "CpEapTlsMethodsUiCaCertAutomatic");
    mCaCertAutomatic->setContentWidgetData(
        "text", 
        hbTrId("txt_occ_setlabel_authority_certificate_val_select"));
    
    // Initialize the value from EapQtConfig
    // Select CA Cert automatically is selected by default
    mCaCertAutomatic->setContentWidgetData(
        "checkState", 
        boolToCheckState(mEapConfig.value(EapQtConfig::AuthorityCertificateAutomatic).toBool()));
    
    // connect signal to disable/enable CA cert when CaCertAutomatic changed 
    mForm->addConnection(
        mCaCertAutomatic, 
        SIGNAL(stateChanged(int)), 
        this,
        SLOT(authorityCertAutomaticChanged(int)));
    
    // Authority certificate comboBox
    mCaCert = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_authority_certificate"));
    mGroupItem->appendChild(mCaCert);
    
    mCaCert->setContentWidgetData("objectName", "CpEapTlsMethodsUiCaCertSelector");
    
    // Stored certificate from EAP configuration
    QList<QVariant> storedCertsList = mEapConfig.value(EapQtConfig::AuthorityCertificate).toList();
    EapQtCertificateInfo storedCert;
    if (!storedCertsList.empty() && storedCertsList[FirstItem].canConvert<EapQtCertificateInfo> ()) {
        // Stored certificate found, index is still unknown 
        storedCert = storedCertsList[FirstItem].value<EapQtCertificateInfo> ();
        mCurrentAuthorityCert = UnknownIndex;
    } else {
        // no selected certificate, use 'not in use'
        mCurrentAuthorityCert = DefaultIndex;
    }

    // Authority certificates found from system
    mAuthorityCerts = mConfigIf->certificateAuthorityCertificates();
    
    // List of comboBox items
    QStringList items;
    // Add 'Not in use' to comboBox list
    items << hbTrId("txt_occ_setlabel_authority_certificate_val_not_in");
    // Add certificates to comboBox list and find index of stored certificate 
    for (int i = 0; i < mAuthorityCerts.count(); ++i) {
        items << mAuthorityCerts.at(i).value(EapQtCertificateInfo::CertificateLabel).toString();
        if (mCurrentAuthorityCert == UnknownIndex 
            && storedCert.value(EapQtCertificateInfo::SubjectKeyId)
            == mAuthorityCerts.at(i).value(EapQtCertificateInfo::SubjectKeyId)) {
            mCurrentAuthorityCert = i + NotInUseShift;
        }
    }
    if (mCurrentAuthorityCert == UnknownIndex) {
        // Selected certificate not found in the certificate list
        mCurrentAuthorityCert = DefaultIndex;
    }
    
    // Initialize Authority certificates comboBox
    mCaCert->setContentWidgetData("items", items);
    mCaCert->setContentWidgetData("currentIndex", mCurrentAuthorityCert);
    
    // Get info when authority certificate selection has been changed
    mForm->addConnection(
        mCaCert, 
        SIGNAL(currentIndexChanged(int)), 
        this,
        SLOT(authorityCertChanged(int)));
    
    // Dim authority certificate if select automatically checked
    authorityCertAutomaticChanged(mCaCertAutomatic->contentWidgetData("checkState") == Qt::Checked);
}

/*!
 * Creates PEAP version selection comboBox
 */
void CpEapTlsMethodsUi::createPeapVersion()
{
    qDebug("CpEapTlsMethodsUi::createPeapVersion()");
    // Create PEAP version comboBox
    mPeapVersion = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_peap_version"));
    mGroupItem->appendChild(mPeapVersion);
    
    mPeapVersion->setContentWidgetData("objectName", "CpEapTlsMethodsUiPeapVersionSelector");
    
    // Add items to comboBox List
    QStringList items;
    items << hbTrId("txt_occ_setlabel_peap_version_val_peapv0")
        << hbTrId("txt_occ_setlabel_peap_version_val_peapv1")
        << hbTrId("txt_occ_setlabel_peap_version_val_peapv0_or_peapv1");
    mPeapVersion->setContentWidgetData("items", items);
    
    // Initialize PEAP version from EAP configuration
    if (mEapConfig.value(EapQtConfig::PeapVersion0Allowed).toBool()
        && mEapConfig.value(EapQtConfig::PeapVersion1Allowed).toBool()) {
        // PEAPv0 or PEAPv1
        mCurrentPeapVersion = PeapVersionBoth;
    } else if (mEapConfig.value(EapQtConfig::PeapVersion1Allowed).toBool()) {
        // PEAPv1
        mCurrentPeapVersion = PeapVersion1;
    } else if (mEapConfig.value(EapQtConfig::PeapVersion0Allowed).toBool()) {
        // PEAPv0
        mCurrentPeapVersion = PeapVersion0;
    } else {
        qDebug("CpEapTlsMethodsUi::createPeapVersion() - unknown version");    
        // Set default (PEAPv0 or PEAPv1)
        mCurrentPeapVersion = PeapVersionBoth;
    }
    mPeapVersion->setContentWidgetData("currentIndex", mCurrentPeapVersion);

    // Get info when PEAP version selection has been changed
    mForm->addConnection(
        mPeapVersion, 
        SIGNAL(currentIndexChanged(int)), 
        this,
        SLOT(peapVersionChanged(int)));
}

/*!
 * Creates authenticated and unauthenticated provisioning checkBoxes.
 */
void CpEapTlsMethodsUi::createProvisioning()
{
    qDebug("CpEapTlsMethodsUi::createProvisioning()");
    // Authenticated provisioning
    mAuthProvisioning = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_authenticated_provisioning"));
    mGroupItem->appendChild(mAuthProvisioning);
    
    mAuthProvisioning->setContentWidgetData(
        "objectName", 
        "CpEapTlsMethodsUiAuthProvisioning");
    mAuthProvisioning->setContentWidgetData(
        "text", 
        hbTrId("txt_occ_setlabel_val_provisioning_enabled"));
    
    // Initialize the value from EapQtConfig
    mAuthProvisioning->setContentWidgetData(
        "checkState", 
        boolToCheckState(mEapConfig.value(
        EapQtConfig::ProvisioningModeAuthenticated).toBool()));
    // Connect signal to disable/enable username when usernameAutomatic changed   
    mForm->addConnection(mAuthProvisioning, SIGNAL(stateChanged(int)), this,
        SLOT(provisioningModeChanged(int)));
    
    // Unauthenticated provisioning
    mUnauthProvisioning = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_unauthenticated_provisioning"));
    mGroupItem->appendChild(mUnauthProvisioning); 
    
    mUnauthProvisioning->setContentWidgetData(
        "objectName", 
        "CpEapTlsMethodsUiUnauthProvisioning");
    mUnauthProvisioning->setContentWidgetData(
        "text", 
        hbTrId("txt_occ_setlabel_val_provisioning_enabled"));
    
    // Initialize the value from EapQtConfig
    mUnauthProvisioning->setContentWidgetData(
        "checkState", 
        boolToCheckState(mEapConfig.value(
        EapQtConfig::ProvisioningModeUnauthenticated).toBool()));
    // Connect signal to disable/enable username when usernameAutomatic changed   
    mForm->addConnection(mUnauthProvisioning, SIGNAL(stateChanged(int)), this,
        SLOT(provisioningModeChanged(int)));
}

/*!
 * Creates TLS privacy selection comboBox
 */
void CpEapTlsMethodsUi::createTlsPrivacy()
{
    qDebug("CpEapTlsMethodsUi::createTlsPrivacy()");
    // Create TLS privacy comboBox
    mTlsPrivacy = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_tls_privacy"));
    mGroupItem->appendChild(mTlsPrivacy);
    
    mTlsPrivacy->setContentWidgetData(
        "objectName", 
        "CpEapTlsMethodsUiTlsPrivacy");
    
    // Add items to comboBox List
    QStringList items;
    items << hbTrId("txt_occ_setlabel_tls_privacy_val_off")
        << hbTrId("txt_occ_setlabel_tls_privacy_val_on");
    mTlsPrivacy->setContentWidgetData("items", items);
    
    // Initialize TLS privacy from EAP configuration
    if (mEapConfig.value(EapQtConfig::UseIdentityPrivacy).toBool()) {
        mTlsPrivacy->setContentWidgetData("currentIndex", TlsPrivacyOn);
    } else {
        mTlsPrivacy->setContentWidgetData("currentIndex", TlsPrivacyOff);
    }
}

/*!
 * Creates inner EAP type selection comboBox and configure button
 */
void CpEapTlsMethodsUi::createInnerMethod()
{
    qDebug("CpEapTlsMethodsUi::createInnerMethod()");
    // Create inner EAP type selection combo box
    createEapSelector();
    // Create 'configure inner EAP type' button
    EapInnerMethodEntryItemData *eapEntry = NULL;
    eapEntry = new EapInnerMethodEntryItemData(
        this, 
        *mItemDataHelper,
        hbTrId("txt_occ_button_inner_eap_type"),
        false);
    
    eapEntry->setContentWidgetData("objectName", "CpEapTlsMethodsUiInnerTypeItem");
    
    mGroupItem->appendChild(eapEntry);    
}

/*!
 * Creates Combo box for inner EAP type selection
 */
void CpEapTlsMethodsUi::createEapSelector()
{
    mInnerEapType = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_inner_eap_type"));
    mGroupItem->appendChild(mInnerEapType);
    
    mInnerEapType->setContentWidgetData("objectName", "CpEapTlsMethodsUiInnerTypeSelector");
    
    // Selected inner EAP type stored into the database
    QList<QVariant> currentEapList = mEapConfig.value(EapQtConfig::InnerType).toList();
    EapQtPluginHandle readInnerEap;
    if (!currentEapList.empty() && currentEapList[FirstItem].canConvert<EapQtPluginHandle> ()) {
        readInnerEap = currentEapList[FirstItem].value<EapQtPluginHandle> ();
        mCurrentInnerPlugin = UnknownIndex;
    } else {
        // no selected inner EAP type, use the first one
        mCurrentInnerPlugin = DefaultIndex;
        mDefaultPluginInUse = true;
    }
    
    for (int i = 0; i < mPlugins.count(); ++i) {
        // Add certificate to comboBox list
        mInnerEapItems << mPlugins.at(i).localizationId();
        if (mCurrentInnerPlugin == UnknownIndex && readInnerEap.pluginId() 
            == mPlugins.at(i).pluginHandle().pluginId()) {
            // Store index of selected certificate
            mCurrentInnerPlugin = i;
        }
        if (mPlugins.at(i).pluginHandle().pluginId() == EapQtPluginHandle::PluginEapMschapv2) {
            // Store index of EAP-MSCHAPv2 (used as default with PEAP and unauthenticated FAST)
            mInnerEapMschapv2 = i;
            mMschapv2Items << mPlugins.at(i).localizationId();
        } else if (mPlugins.at(i).pluginHandle().pluginId() == EapQtPluginHandle::PluginEapGtc) {
            // Store index of EAP-GTC (Used as default with PEAPv1)
            mInnerEapGtc = i;
        }
    }
    if (mCurrentInnerPlugin == UnknownIndex) {
        // Selected inner EAP type not found
        mCurrentInnerPlugin = DefaultIndex;
        mDefaultPluginInUse = true;      
    }
    
    mInnerEapType->setContentWidgetData("items", mInnerEapItems);
    mInnerEapType->setContentWidgetData("currentIndex", mCurrentInnerPlugin);
    
    mForm->addConnection(mInnerEapType, SIGNAL(currentIndexChanged(int)), this,
        SLOT(innerEapTypeChanged(int)));
}

/*!
 * Creates second inner EAP type selection comboBox and configure button
 */
void CpEapTlsMethodsUi::createSecondInnerMethod()
{
    qDebug("CpEapTlsMethodsUi::createSecondInnerMethod()");
    // Create second inner EAP type selection combo box
    createSecondEapSelector();
    // Create 'configure inner EAP type' button
    mSecondEapEntry = new EapInnerMethodEntryItemData(
        this, 
        *mItemDataHelper,
        hbTrId("txt_occ_button_inner_eap_type"),
        true);
    
    mSecondEapEntry->setContentWidgetData("objectName", "CpEapTlsMethodsUiSecondInnerTypeItem");
    
    mGroupItem->appendChild(mSecondEapEntry);    
}

/*!
 * Creates Combo box for second inner EAP type selection
 */
void CpEapTlsMethodsUi::createSecondEapSelector()
{
    mSecondInnerEapType = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_second_inner_eap_type"));
    mGroupItem->appendChild(mSecondInnerEapType);
    
    mSecondInnerEapType->setContentWidgetData("objectName", "CpEapTlsMethodsUiSecondInnerTypeSelector");

    // Selected inner EAP type stored into the database
    QList<QVariant> currentEapList = mEapConfig.value(EapQtConfig::InnerType).toList();
    EapQtPluginHandle readInnerEap;
    if (currentEapList.count() > SecondItem && currentEapList[SecondItem].canConvert<EapQtPluginHandle> ()) {
        readInnerEap = currentEapList[SecondItem].value<EapQtPluginHandle> ();
        mCurrentSecondInnerPlugin = UnknownIndex;
    } else {
        // no selected inner EAP type, use the 'Not in use'
        mCurrentSecondInnerPlugin = NotInUseIndex;
    }
 
    // Add 'Not in use' and EAP-GTC into the combobox list
    QStringList items;
    items << hbTrId("txt_occ_setlabel_second_inner_eap_val_not_in_use");
    if (mInnerEapGtc >= 0) {
        // EAP-GTC plugin is found, add it as the second item of the list
        mSecondInnerEapGtc = SecondItem;
        items << mPlugins.at(mInnerEapGtc).localizationId();
        if (readInnerEap.pluginId() 
            == mPlugins.at(mInnerEapGtc).pluginHandle().pluginId()) {
            mCurrentSecondInnerPlugin = mSecondInnerEapGtc;
        }
    }

    if (mCurrentSecondInnerPlugin == UnknownIndex) {
        // Selected inner EAP type not found
        mCurrentSecondInnerPlugin = NotInUseIndex;     
    }
    
    mSecondInnerEapType->setContentWidgetData("items", items);
    mSecondInnerEapType->setContentWidgetData("currentIndex", mCurrentSecondInnerPlugin);
    
    mForm->addConnection(mSecondInnerEapType, SIGNAL(currentIndexChanged(int)), this,
        SLOT(secondInnerEapTypeChanged(int)));
}

/*!
 * Creates PAC store group
 */
void CpEapTlsMethodsUi::createPacStoreGroup()
{
    qDebug("CpEapTlsMethodsUi::createPacStoreGroup()");
    
    mPacStoreUi = new CpEapPacStoreUi(mConfigIf.data());
    mGroupItemPacStore = mPacStoreUi->uiInstance(
        *mItemDataHelper);
 
    mGroupItemPacStore->setContentWidgetData("objectName", "CpEapTlsMethodsUiPacStoreGroupItem");
    mModel->appendDataFormItem(mGroupItemPacStore);
}

/*!
 * Adds validators.
 * 
 * @param [in] modelIndex   Model index
 */
void CpEapTlsMethodsUi::setValidator(const QModelIndex modelIndex)
{
    qDebug("CpEapTlsMethodsUi::itemActivated");

    HbDataFormViewItem *viewItem = qobject_cast<HbDataFormViewItem *>
        (mForm->itemByIndex(modelIndex));
    HbDataFormModelItem *modelItem = mModel->itemFromIndex(modelIndex);
    
    if (modelItem == mUsername) {
        // When username lineEdit is activated (shown) first time, validator is added
        mValidatorUsername.reset(
            mConfigIf->validatorEap(
                mPluginInfo.pluginHandle().type(),
                EapQtConfig::Username));
        
        HbLineEdit *edit = qobject_cast<HbLineEdit *> (viewItem->dataItemContentWidget());
        mValidatorUsername->updateEditor(edit);
    } else if (modelItem == mRealm) {
        // When realm lineEdit is activated (shown) first time, validator is added
        mValidatorRealm.reset(
            mConfigIf->validatorEap(
                mPluginInfo.pluginHandle().type(),
                EapQtConfig::Realm));
        
        HbLineEdit *edit = qobject_cast<HbLineEdit *> (viewItem->dataItemContentWidget());
        mValidatorRealm->updateEditor(edit);
    }
}

/*!
 * Sets default Inner EAP method according PEAP version
 */
void CpEapTlsMethodsUi::defaultInnerPlugin()
{
    qDebug("CpEapTlsMethodsUi::defaultInnerPlugin()");
    if (mCurrentPeapVersion == PeapVersion1 && mInnerEapGtc >= 0) {
        mInnerEapType->setContentWidgetData("currentIndex", mInnerEapGtc);
        mCurrentInnerPlugin = mInnerEapGtc;
    } else if (mInnerEapMschapv2 >= 0){
        mInnerEapType->setContentWidgetData("currentIndex", mInnerEapMschapv2);
        mCurrentInnerPlugin = mInnerEapMschapv2;
    } else {
        // Both EAP-GTC and EAP-MSCHAPv2 should always be supported
        // so here should never come
        qDebug("CpEapTlsMethodsUi::defaultInnerPlugin(): No suitable inner EAP type");
    }
}

/*!
 * Stores the index of selected user certificate
 * 
 * @param [in] value  Index of selected certificate.
 */
void CpEapTlsMethodsUi::userCertChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::userCertChanged()");
    mCurrentUserCert = value;
}

/*!
 * Stores the index of selected authority certificate
 * 
 * @param [in] value  Index of selected certificate.
 */
void CpEapTlsMethodsUi::authorityCertChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::authorityCertChanged()");
    mCurrentAuthorityCert = value;
}

/*!
 * Stores the index of selected PEAP version
 * 
 * @param [in] value  Index of selected PEAP version.
 */
void CpEapTlsMethodsUi::peapVersionChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::peapVersionChanged()");
    mCurrentPeapVersion = value;
    defaultInnerPlugin();
}

/*!
 * Stores the index of selected inner EAP type
 * 
 * @param [in] value  Index of selected inner EAP type.
 */
void CpEapTlsMethodsUi::innerEapTypeChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::innerEapTypeChanged()");
    if (!mInnerEapMschapv2Only) {
        mCurrentInnerPlugin = value; 
    }
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapFast) {
        // If Inner EAP typ is EAP-MSCHAPv2 the second inner EAP type
        // is EAP-GTC by default otherwise 'Not in use'
        if (mInnerEapMschapv2Only || mCurrentInnerPlugin == mInnerEapMschapv2) {
            mSecondInnerEapType->setContentWidgetData(
                "currentIndex", mSecondInnerEapGtc);
        } else {
            mSecondInnerEapType->setContentWidgetData(
                "currentIndex", NotInUseIndex);                
        }
        if (mInnerEapMschapv2Only) {
            mSecondInnerEapType->setContentWidgetData("enabled", true);
        } else {
            mSecondInnerEapType->setContentWidgetData("enabled", false);
        }
    }
}

/*!
 * Stores the index of selected second inner EAP type and
 * dims the 'Configure inner EAP type' button if 'Not in use' has been selected
 * 
 * @param [in] value  Index of selected second inner EAP type.
 */
void CpEapTlsMethodsUi::secondInnerEapTypeChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::secondInerEapTypeChanged()");
    mCurrentSecondInnerPlugin = value;
    if (value == NotInUseIndex || !mSecondInnerEapType->contentWidgetData("enabled").toBool()) {
        // If 'Not in use' selected 'Configure inner EAP type' button is dimmed
        mSecondEapEntry->setContentWidgetData("enabled", false);
    } else {
        // If EAP-GTC selected 'Configure inner EAP type' button is available
        mSecondEapEntry->setContentWidgetData("enabled", true);
    }
}

/*!
 * Dims the username if generate username automatically has been selected.
 * 
 * @param [in] state  Tells is username generate automatically checked.
 */
void CpEapTlsMethodsUi::usernameAutomaticChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::usernameAutomaticChanged");

    mUsername->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Dims the realm if generate realm automatically has been selected.
 * 
 * @param [in] state  Tells is realm generate automatically checked.
 */
void CpEapTlsMethodsUi::realmAutomaticChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::realmAutomaticChanged");

    mRealm->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Dims the authority certificate if select caCert automatically has been selected.
 * 
 * @param [in] state  Tells is authority certificate select automatically checked.
 */
void CpEapTlsMethodsUi::authorityCertAutomaticChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::authorityCertAutomaticChanged");

    mCaCert->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Dims all fields except inner EAP types and provisionig modes 
 * if Unauthenticated provisioning mode is selected
 * and Authenticated provisioning is not selceted
 *
 *  @param [in] state  Obsolete parameter, not needed
 */
void CpEapTlsMethodsUi::provisioningModeChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::provisioningModeChanged");
    
    Q_UNUSED(state);
    
    // If only unauthenticated provisioning is selected all fields are dimmed 
    // except the first (EAP-MSCHAPv2) and the second (EAP-GTC) inner EAP type 
    // settings and authenticated provisioning can be selected
    // Else all fields are available
    if (mUnauthProvisioning->contentWidgetData(
            "checkState") == Qt::Checked
        && mAuthProvisioning->contentWidgetData(
            "checkState") == Qt::Unchecked) {
        mCaCertAutomatic->setContentWidgetData("enabled", false);
        mCaCert->setContentWidgetData("enabled", false);
        mUserCertificate->setContentWidgetData("enabled", false);
        mUsernameAutomatic->setContentWidgetData("enabled", false);
        mUsername->setContentWidgetData("enabled", false);
        mRealmAutomatic->setContentWidgetData("enabled", false);
        mRealm->setContentWidgetData("enabled", false);
        mTlsPrivacy->setContentWidgetData("enabled", false);
        mInnerEapMschapv2Only = true;
        mSecondInnerEapType->setContentWidgetData("enabled", true);
        mSecondEapEntry->setContentWidgetData("enabled", true);
        mInnerEapType->setContentWidgetData("items", mMschapv2Items);
    } else {
        mCaCertAutomatic->setContentWidgetData("enabled", true);
        mCaCert->setContentWidgetData("enabled", !checkStateToBool(
            mCaCertAutomatic->contentWidgetData("checkState").toInt()));
        mUserCertificate->setContentWidgetData("enabled", true);
        mUsernameAutomatic->setContentWidgetData("enabled", true);
        mUsername->setContentWidgetData("enabled", !checkStateToBool(
            mUsernameAutomatic->contentWidgetData("checkState").toInt()));
        mRealmAutomatic->setContentWidgetData("enabled", true);
        mRealm->setContentWidgetData("enabled", !checkStateToBool(
            mRealmAutomatic->contentWidgetData("checkState").toInt()));
        mTlsPrivacy->setContentWidgetData("enabled", true);
        if (mUnauthProvisioning->contentWidgetData(
            "checkState") == Qt::Checked) {
            // When Unauthenticated provisioning is selected only EAP-MSCHAPv2 is
            // supported as first inner EAP type. Second inner EAP type is available
            mInnerEapMschapv2Only = true;
            mSecondInnerEapType->setContentWidgetData("enabled", true);
            mSecondEapEntry->setContentWidgetData("enabled", true);
            mInnerEapType->setContentWidgetData("items", mMschapv2Items);

        } else {
            // When Unauthenticated provisioning is not selected all inner EAP
            // types are shown in the first inner EAP type list and 
            // the second inner EAP type is dimmed
            mInnerEapMschapv2Only = false;
            mForm->removeConnection(mInnerEapType, SIGNAL(currentIndexChanged(int)), this,
                SLOT(innerEapTypeChanged(int)));
            mInnerEapType->setContentWidgetData("items", mInnerEapItems);
            mForm->addConnection(mInnerEapType, SIGNAL(currentIndexChanged(int)), this,
                SLOT(innerEapTypeChanged(int)));
            mInnerEapType->setContentWidgetData("currentIndex", mCurrentInnerPlugin);
            mSecondInnerEapType->setContentWidgetData("enabled", false);
            mSecondEapEntry->setContentWidgetData("enabled", false);
        }
    }
}

/*!
 * Slot for close the view after confirmed.
 * 
 * @param [in] action  User action
 */
void CpEapTlsMethodsUi::incompletedSettingsConfirmed(int action)
{
    qDebug("CpEapTlsMethodsUi::incompletedSettingsConfirmed()");
    if (action == HbMessageBox::Yes) {
        // User Clicked Yes
        // Close view
        qDebug("CpEapTlsMethodsUi::incompletedSettingsConfirmed(): YES");
        emit aboutToClose();
    } else{
        // User Clicked No
        // Don't close the view
        Q_ASSERT(action == HbMessageBox::No);
        qDebug("CpEapTlsMethodsUi::incompletedSettingsConfirmed(): NO");  
    }
}

/*!
 * Slot for close the view after user has been informed.
 * 
 * @param [in] action  User action
 */
void CpEapTlsMethodsUi::unableToSaveSettingsClosed(int action)
{
    qDebug("CpEapTlsMethodsUi::unableToSaveSettingsClosed()");
    if (action == HbMessageBox::Ok) {
        // User Clicked Ok
        // Close view
        qDebug("CpEapTlsMethodsUi::unableToSaveSettingsClosed(): OK");
        emit aboutToClose();
    }    
}

/*!
 * Converts check box state to boolean.
 * 
 * @param [in] state  Check box state
 * 
 * @return true if Check box is checked, false otherwise.
 */
bool CpEapTlsMethodsUi::checkStateToBool(const int state)
{
    return (Qt::Unchecked == state ? false : true);
}

/*!
 * Converts boolean to check box state.
 * 
 * @param [in] state  Tells is check box checked.
 * 
 * @return Qt check state
 */
int CpEapTlsMethodsUi::boolToCheckState(const bool state)
{
    return (false == state ? Qt::Unchecked : Qt::Checked);
}

/*!
 * This is called when user is about to exit the view.
 * Validates configuration and saves settings.
 * If configuration is not valid prompts question dialog.
 * If user chooses "OK" leaves without saving.
 * 
 */
void CpEapTlsMethodsUi::close()
{
    qDebug("CpEapTlsMethodsUi::close");
    
    // Validate configuration
    if (validate()) {
        qDebug("CpEapTlsMethodsUi::close - Validation OK");
        
        // Store settings
        if (storeSettings()){
            qDebug("CpEapTlsMethodsUi::close - Settings stored, close view");
            // Close view
            CpBaseSettingView::close();   
        } else {
            qDebug("CpEapTlsMethodsUi::close - Store settings failed, prompt warning");
            // Store failed. Show error note to user
            HbMessageBox *warningBox = new HbMessageBox(HbMessageBox::MessageTypeWarning);
            warningBox->setObjectName("CpEapTlsMethodsUiStoreFailedWarning");
            warningBox->setText(hbTrId("txt_occ_info_unable_to_save_setting"));
            warningBox->setAttribute(Qt::WA_DeleteOnClose);
            warningBox->setStandardButtons(HbMessageBox::Ok);
            warningBox->open(this,SLOT(unableToSaveSettingsClosed(int)));
        }
    } else {
        qDebug("CpEapTlsMethodsUi::close - validation failed. Prompt question.");

        // Validate failed. Request user to exit anyway
        HbMessageBox *questionBox = new HbMessageBox(HbMessageBox::MessageTypeQuestion);
        questionBox->setObjectName("CpEapTlsMethodsUiExitWithoutSavingQuestion");
        questionBox->setText(hbTrId("txt_occ_info_incomplete_details_return_without_sa"));
        questionBox->setAttribute(Qt::WA_DeleteOnClose);
        questionBox->setStandardButtons(HbMessageBox::Yes | HbMessageBox::No);
        questionBox->open(this,SLOT(incompletedSettingsConfirmed(int)));
    }
}

/*!
 * Validates settings configuration.
 * 
 * @return true if configuration OK, false otherwise.
 */
bool CpEapTlsMethodsUi::validate()
{
    qDebug("CpEapTlsMethodsUi::validate()");
    bool valid = false;

    if (validateUsernameGroup() 
        && validateRealmGroup()
        && validateAuthorityCertificate()
        && validateUserCertificate()
        && validateCiphersuites()) {
        valid = true;
    }

    return valid;
}

/*!
 * Validates username checkBox and lineEdit group.
 * 
 * @return true if OK, false otherwise.
 */
bool CpEapTlsMethodsUi::validateUsernameGroup()
{
    bool status = false;
    // true if generate automatically is checked or given value is valid
    if (mUsernameAutomatic->contentWidgetData("checkState") == Qt::Checked
        || EapQtValidator::StatusOk == mValidatorUsername->validate(
            mUsername->contentWidgetData("text"))) {
        status = true;
    }
    qDebug("CpEapTlsMethodsUi::validateUsernameGroup() - status: %d", status);
    return status;
}

/*!
 * Validates realm checkBox and lineEdit group.
 * 
 * @return true if OK, false otherwise.
 */
bool CpEapTlsMethodsUi::validateRealmGroup()
{
    bool status = false;
    // true if generate automatically is checked or given value is valid
    if (mRealmAutomatic->contentWidgetData("checkState") == Qt::Checked
        || EapQtValidator::StatusOk == mValidatorRealm->validate(
            mRealm->contentWidgetData("text"))) {
        status = true;
    }
    qDebug("CpEapTlsMethodsUi::validateRealmGroup() - status: %d", status);
    return status;
}

/*!
 * Validates authority certificate checkBox and comboBox group.
 * 
 * @return true if OK, false otherwise.
 */
bool CpEapTlsMethodsUi::validateAuthorityCertificate()
{
    bool status = false;
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapFast) {
        // Always true for EAP-FAST
        status = true;
    } else {    
        //true if select automatically is checked or certificate is selected
        if (mCaCertAutomatic->contentWidgetData("checkState") == Qt::Checked
            || mCurrentAuthorityCert > NotInUseIndex) {
            status = true;
        }
    }
    qDebug("CpEapTlsMethodsUi::validateAuthorityCertificate()- status: %d", status);
    return status;
}

/*!
 * Validates user certificate selection.
 * 
 * @return false if EAP-TLS and no certificate, true otherwise
 */
bool CpEapTlsMethodsUi::validateUserCertificate()
{
    bool status = true;
    // false if EAP-TLS and not selected user certificate
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapTls
        && mCurrentUserCert == NotInUseIndex) {
        status = false;
    }
    qDebug("CpEapTlsMethodsUi::validateUserCertificate() - status: %d", status);
    return status;
}

/*!
 * Validates cipher suites selection.
 * 
 * @return false if no cipher suite is selected, true otherwise
 */
bool CpEapTlsMethodsUi::validateCiphersuites()
{
    bool status = true;
    QVariant cipherSuites = mGroupItemCs->ciphersuites();
    QList<QVariant> cipherList = cipherSuites.toList();
    if (cipherList.count() == 0){
        status = false;
    }
    qDebug("CpEapTlsMethodsUi::validateCiphersuites() - status: %d", status);
    return status;
}

/*!
 * Write PEAP specific values into the EAP configuration
 * 
 * @param [out] eapConfig  EAP configuration settings
 */
void CpEapTlsMethodsUi::setPeapVersion(EapQtConfig &eapConfig)
{
    qDebug("CpEapTlsMethodsUi::setPeapVersion()");
    if (mCurrentPeapVersion == PeapVersion0) {
        eapConfig.setValue(EapQtConfig::PeapVersion0Allowed, true);
        eapConfig.setValue(EapQtConfig::PeapVersion1Allowed, false);
    } else if (mCurrentPeapVersion == PeapVersion1) {
        eapConfig.setValue(EapQtConfig::PeapVersion0Allowed, false);
        eapConfig.setValue(EapQtConfig::PeapVersion1Allowed, true);            
    } else {
        Q_ASSERT(mCurrentPeapVersion == PeapVersionBoth);
        eapConfig.setValue(EapQtConfig::PeapVersion0Allowed, true);
        eapConfig.setValue(EapQtConfig::PeapVersion1Allowed, true);            
    }    
}

/*!
 * Write FAST specific values into the EAP configuration
 * 
 * @param [out] eapConfig  EAP configuration settings
 */
void CpEapTlsMethodsUi::setFastSettings(EapQtConfig &eapConfig)
{
    qDebug("CpEapTlsMethodsUi::setFastSettings()");
    // Provisioning Mode
    eapConfig.setValue(
        EapQtConfig::ProvisioningModeAuthenticated,
        checkStateToBool(mAuthProvisioning->contentWidgetData(
            "checkState").toInt()));
    eapConfig.setValue(
        EapQtConfig::ProvisioningModeUnauthenticated,
        checkStateToBool(mUnauthProvisioning->contentWidgetData(
            "checkState").toInt()));
    
    // TLS privacy
    if (mTlsPrivacy->contentWidgetData("currentIndex") == TlsPrivacyOn) {
        eapConfig.setValue(EapQtConfig::UseIdentityPrivacy, true);
    } else {
        eapConfig.setValue(EapQtConfig::UseIdentityPrivacy, false);
    }
}

/*!
 * Stores settings given via TLS based methods setting UI
 * 
 * @return false if saving failed, true otherwise
 */
bool CpEapTlsMethodsUi::storeSettings()
{
    qDebug("CpEapTlsMethodsUi::storeSettings");

    EapQtConfig eapConfig;

    // Store common settings
    qDebug("CpEapTlsMethodsUi::storeSettings - Common settings");
    eapConfig.setValue(
        EapQtConfig::OuterType, 
        qVariantFromValue(mOuterHandle));
    
    eapConfig.setValue(
        EapQtConfig::UsernameAutomatic, 
        checkStateToBool(mUsernameAutomatic->contentWidgetData("checkState").toInt()));
    
    eapConfig.setValue(
        EapQtConfig::Username, 
        mUsername->contentWidgetData("text"));
    
    eapConfig.setValue(
        EapQtConfig::RealmAutomatic, 
        checkStateToBool(mRealmAutomatic->contentWidgetData("checkState").toInt()));
    
    eapConfig.setValue(
        EapQtConfig::Realm, 
        mRealm->contentWidgetData("text"));

    // User certificate
    qDebug("CpEapTlsMethodsUi::storeSettings - User certificate");
    if (mCurrentUserCert > NotInUseIndex) {
        QList<QVariant> userCerts;
        userCerts.append(qVariantFromValue(mUserCerts.at(mCurrentUserCert - 1)));
        // The first item in UI(index 0) is 'not in use'
        eapConfig.setValue(EapQtConfig::UserCertificate, userCerts); 
    }

    // Authority certificate
    qDebug("CpEapTlsMethodsUi::storeSettings - Authority certificate");
    eapConfig.setValue(EapQtConfig::AuthorityCertificateAutomatic, checkStateToBool(
        mCaCertAutomatic->contentWidgetData("checkState").toInt()));
    if (mCurrentAuthorityCert > NotInUseIndex && !checkStateToBool(
        mCaCertAutomatic->contentWidgetData("checkState").toInt())) {
        QList<QVariant> authorityCerts;
        authorityCerts.append(qVariantFromValue(mAuthorityCerts.at(mCurrentAuthorityCert - 1)));
        // The first item in UI(index 0) is 'not in use'
        eapConfig.setValue(EapQtConfig::AuthorityCertificate, authorityCerts); 
    }    
    
    // Inner EAP method (Not valid for EAP-TLS)
    if (!(mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapTls)) {
        qDebug("CpEapTlsMethodsUi::storeSettings - Inner EAP method");
        if (!mPlugins.isEmpty()) {
            QList<QVariant> innerEaps;
            if (mInnerEapMschapv2Only) {
                innerEaps.append(qVariantFromValue(mPlugins.at(mInnerEapMschapv2).pluginHandle()));
            } else {
                innerEaps.append(qVariantFromValue(mPlugins.at(mCurrentInnerPlugin).pluginHandle()));
            }
            if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapFast){
                // Second inner eap can be 'Not in use' or EAP-GTC
                if (mCurrentSecondInnerPlugin != NotInUseIndex){
                    innerEaps.append(qVariantFromValue(
                        mPlugins.at(mInnerEapGtc).pluginHandle()));
                }
            }
            eapConfig.setValue(EapQtConfig::InnerType, innerEaps);
        }
    }

    // Cipher suites
    qDebug("CpEapTlsMethodsUi::storeSettings - Cipher suites");
    eapConfig.setValue(EapQtConfig::CipherSuites, mGroupItemCs->ciphersuites());
    

    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginPeap) {
        // PEAP version (valid only for PEAP)
        setPeapVersion(eapConfig);
    } else if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapFast) {
        // FAST specific settings
        setFastSettings(eapConfig);
    }
    
    // Save configuration
    if (!mConfigIf->saveConfiguration(mPluginInfo.pluginHandle(), eapConfig)) {
        qDebug("CpEapTlsMethodsUi::storeSettings - configuration saving failed.");
        return false;
    }
    return true;
}

