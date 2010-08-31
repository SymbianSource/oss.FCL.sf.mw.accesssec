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
 * %version: 24 %
 */

// System includes
#include <HbDataForm>
#include <HbDataFormModel>
#include <HbDataFormViewItem>
#include <HbParameterLengthLimiter>
#include <HbMessageBox> 
#include <HbAction>
#include <HbLineEdit>
#include <cpsettingformitemdata.h>
#include <cpitemdatahelper.h>
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtcertificateinfo.h>
#include <cppluginutility.h>

// User includes
#include "cpeapciphersuiteui.h"
#include "cpeaptlsmethodsui.h"
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

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param bearer        Bearer type of the accessed configuration.
 * @param iapId         IAP ID of the accessed configuration.
 * @param plugin        Plugin.
 * @param outerHandle   Outer handle.
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
        mCaCertAutomatic(NULL),
        mCaCert(NULL),
        mPeapVersion(NULL),
        mInnerEapType(NULL),
        mGroupItemCs(NULL),
        mCurrentUserCert(0),
        mCurrentAuthorityCert(0),
        mCurrentPeapVersion(0),
        mCurrentInnerPlugin(0),
        mInnerEapMschapv2(0),
        mInnerEapGtc(0),
        mDefaultPluginInUse(false)
{
    qDebug("CpEapTlsMethodsUi::CpEapTlsMethodsUi()");

    // IAP must be valid in construction (check includes
    // EapQtConfigInterface::IapIdUndefined)
    if (iapId < 0) {
        QT_THROW(std::bad_alloc());
        // scoped pointer gets deleted automaticaly on exception
    }

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
    return mConfigIf->uiInstance(mPluginInfo.pluginHandle(),
        mPlugins.at(mCurrentInnerPlugin).pluginHandle());
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
    this->setWidget(mForm);
    CpPluginUtility::addCpItemPrototype(mForm);
    mModel = new HbDataFormModel(mForm);
    
    // Create settings group
    mGroupItem = new HbDataFormModelItem(HbDataFormModelItem::GroupItem,
        HbParameterLengthLimiter(
            hbTrId("txt_occ_subhead_eap_module_settings")).arg(
            mPluginInfo.localizationId()));
    mModel->appendDataFormItem(mGroupItem);

    // The parameter given as 0 is a HbDataForm pointer, not parent
    mItemDataHelper = new CpItemDataHelper(0);
    mItemDataHelper->setParent(this);

    // Create method specific UI
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapTls) {
        createTlsUi();
    }
    else if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginEapTtls) {
        createTtlsUi();
    }
    else if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginPeap) {
        createPeapUi();
    }
    else {
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
    bool connected = connect(mForm, SIGNAL( itemShown(const QModelIndex&) ), this,
        SLOT( setValidator(const QModelIndex) ));
    Q_ASSERT(connected); 
    
    // Expand TLS based method settings group
    mForm->setExpanded(mModel->indexFromItem(mGroupItem), true);
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
 * Creates Username group:
 * Generate automatically checkBox and username lineEdit
 */
void CpEapTlsMethodsUi::createUsername()
{
    qDebug("CpEapTlsMethodsUi::createUsername()");
    // UsernameAutomatic
    mUsernameAutomatic = new CpSettingFormItemData(HbDataFormModelItem::CheckBoxItem, hbTrId(
        "txt_occ_setlabel_user_name"));
    mUsernameAutomatic->setContentWidgetData("text", hbTrId(
        "txt_occ_setlabel_user_name_val_generate_automatica"));
    // Initialize the value from EapQtConfig
    // Generate username automatically is selected by default
    mUsernameAutomatic->setContentWidgetData("checkState", boolToCheckState(mEapConfig.value(
        EapQtConfig::UsernameAutomatic).toBool()));
    // Connect signal to disable/enable username when usernameAutomatic changed   
    mForm->addConnection(mUsernameAutomatic, SIGNAL(stateChanged(int)), this,
        SLOT(usernameAutomaticChanged(int)));
    mGroupItem->appendChild(mUsernameAutomatic);

    //Username
    mUsername = new CpSettingFormItemData(HbDataFormModelItem::TextItem, hbTrId(
        "txt_occ_setlabel_user_name"));
    mUsername->setContentWidgetData("text", mEapConfig.value(EapQtConfig::Username));
    // Dim username if usernameAutomatic selected
    usernameAutomaticChanged(mUsernameAutomatic->contentWidgetData("checkState") == Qt::Checked);
    mGroupItem->appendChild(mUsername);
}

/*!
 * Creates Realm group:
 * Generate automatically checkBox and realm lineEdit
 */
void CpEapTlsMethodsUi::createRealm()
{
    qDebug("CpEapTlsMethodsUi::createRealm()");
    // RealmAutomatic
    mRealmAutomatic = new CpSettingFormItemData(HbDataFormModelItem::CheckBoxItem, hbTrId(
        "txt_occ_setlabel_realm"));
    mRealmAutomatic->setContentWidgetData("text", hbTrId(
        "txt_occ_setlabel_realm_val_generate_automatically"));
    // Initialize the value from EapQtConfig
    // Generate realm automatically is selected by default
    mRealmAutomatic->setContentWidgetData("checkState", boolToCheckState(mEapConfig.value(
        EapQtConfig::RealmAutomatic).toBool()));
    // connect signal to disable/enable realm when realmAutomatic changed 
    mForm->addConnection(mRealmAutomatic, SIGNAL(stateChanged(int)), this,
        SLOT(realmAutomaticChanged(int)));
    mGroupItem->appendChild(mRealmAutomatic);

    //Realm
    mRealm = new CpSettingFormItemData(HbDataFormModelItem::TextItem, hbTrId(
        "txt_occ_setlabel_realm"));
    mRealm->setContentWidgetData("text", mEapConfig.value(EapQtConfig::Realm));
    // Dim realm if realmAutomatic selected
    realmAutomaticChanged(mRealmAutomatic->contentWidgetData("checkState") == Qt::Checked);
    mGroupItem->appendChild(mRealm); 
}

/*!
 * Creates User certificate selection comboBox
 */
void CpEapTlsMethodsUi::createUserCerts()
{
    qDebug("CpEapTlsMethodsUi::createUserCerts()");
    // Create User certificate comboBox
    CpSettingFormItemData *userCertList = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_user_certificate"));
    
    // Stored certificate
    QList<QVariant> storedCertsList = mEapConfig.value(EapQtConfig::UserCertificate).toList();
    EapQtCertificateInfo storedCert;
    if (!storedCertsList.empty() && storedCertsList[0].canConvert<EapQtCertificateInfo> ()) {
        // Stored certificate found, index is still unknown 
        storedCert = storedCertsList[0].value<EapQtCertificateInfo> ();
        mCurrentUserCert = UnknownIndex;
    }
    else {
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
            mCurrentUserCert = i + 1;
        }
    }
    if (mCurrentUserCert == UnknownIndex) {
        // Stored certificate not found in the certificate list
        qDebug("CpEapTlsMethodsUi::createUserCerts() - stored certificate not in the list");
        mCurrentUserCert = DefaultIndex;
    }
    
    // Initialize comboBox
    userCertList->setContentWidgetData("items", items);
    userCertList->setContentWidgetData("currentIndex", mCurrentUserCert);
    
    // Get info when user certificate selection has been changed
    mForm->addConnection(userCertList, SIGNAL(currentIndexChanged(int)), this,
        SLOT(userCertChanged(int)));
    mGroupItem->appendChild(userCertList);
}

/*!
 * Creates Authority certs group:
 * Select automatically check box and certificate comboBox
 */
void CpEapTlsMethodsUi::createAuthorityCerts()
{
    qDebug("CpEapTlsMethodsUi::createAuthorityCerts()");
    // Select Authority Certificate Automatically
    mCaCertAutomatic = new CpSettingFormItemData(HbDataFormModelItem::CheckBoxItem, hbTrId(
        "txt_occ_setlabel_authority_certificate"));
    mCaCertAutomatic->setContentWidgetData("text", hbTrId(
        "txt_occ_setlabel_authority_certificate_val_select"));
    // Initialize the value from EapQtConfig
    // Select CA Cert automatically is selected by default
    mCaCertAutomatic->setContentWidgetData("checkState", boolToCheckState(mEapConfig.value(
        EapQtConfig::AuthorityCertificateAutomatic).toBool()));
    // connect signal to disable/enable CA cert when CaCertAutomatic changed 
    mForm->addConnection(mCaCertAutomatic, SIGNAL(stateChanged(int)), this,
        SLOT(authorityCertAutomaticChanged(int)));
    mGroupItem->appendChild(mCaCertAutomatic);
    
    // Authority certificate comboBox
    mCaCert = new CpSettingFormItemData(HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_authority_certificate"));
    
    // Stored certificate from EAP configuration
    QList<QVariant> storedCertsList = mEapConfig.value(EapQtConfig::AuthorityCertificate).toList();
    EapQtCertificateInfo storedCert;
    if (!storedCertsList.empty() && storedCertsList[0].canConvert<EapQtCertificateInfo> ()) {
        // Stored certificate found, index is still unknown 
        storedCert = storedCertsList[0].value<EapQtCertificateInfo> ();
        mCurrentAuthorityCert = UnknownIndex;
    }
    else {
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
            mCurrentAuthorityCert = i + 1;
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
    mForm->addConnection(mCaCert, SIGNAL(currentIndexChanged(int)), this,
        SLOT(authorityCertChanged(int)));
    // Dim authority certificate if select automatically checked
    authorityCertAutomaticChanged(mCaCertAutomatic->contentWidgetData("checkState") == Qt::Checked);
    mGroupItem->appendChild(mCaCert);
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
    }
    else if (mEapConfig.value(EapQtConfig::PeapVersion1Allowed).toBool()) {
        // PEAPv1
        mCurrentPeapVersion = PeapVersion1;
    }
    else if (mEapConfig.value(EapQtConfig::PeapVersion0Allowed).toBool()) {
        // PEAPv0
        mCurrentPeapVersion = PeapVersion0;
    }
    else {
        qDebug("CpEapTlsMethodsUi::createPeapVersion() - unknown version");    
        // Set default (PEAPv0 or PEAPv1)
        mCurrentPeapVersion = PeapVersionBoth;
    }
    mPeapVersion->setContentWidgetData("currentIndex", mCurrentPeapVersion);

    // Get info when PEAP version selection has been changed
    mForm->addConnection(mPeapVersion, SIGNAL(currentIndexChanged(int)), this,
        SLOT(peapVersionChanged(int)));
    mGroupItem->appendChild(mPeapVersion);
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
    eapEntry = new EapInnerMethodEntryItemData(this, *mItemDataHelper,
        hbTrId("txt_occ_button_inner_eap_type"));
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

    // Selected inner EAP type stored into the database
    QList<QVariant> currentEapList = mEapConfig.value(EapQtConfig::InnerType).toList();
    EapQtPluginHandle readInnerEap;
    if (!currentEapList.empty() && currentEapList[0].canConvert<EapQtPluginHandle> ()) {
        readInnerEap = currentEapList[0].value<EapQtPluginHandle> ();
        mCurrentInnerPlugin = UnknownIndex;
    }
    else {
        // no selected inner EAP type, use the first one
        mCurrentInnerPlugin = DefaultIndex;
        mDefaultPluginInUse = true;
    }
    
    QStringList items;
    for (int i = 0; i < mPlugins.count(); ++i) {
        // Add certificate to comboBox list
        items << mPlugins.at(i).localizationId();
        if (mCurrentInnerPlugin == UnknownIndex && readInnerEap.pluginId() 
            == mPlugins.at(i).pluginHandle().pluginId()) {
            // Store index of selected certificate
            mCurrentInnerPlugin = i;
        }
        if (mPlugins.at(i).pluginHandle().pluginId() == EapQtPluginHandle::PluginEapMschapv2) {
            // Store index of EAP-MSCHAPv2 (used as default with PEAP and unauthenticated FAST)
            mInnerEapMschapv2 = i;
        }
        else if (mPlugins.at(i).pluginHandle().pluginId() == EapQtPluginHandle::PluginEapGtc) {
            // Store index of EAP-GTC (Used as default with PEAPv1)
            mInnerEapGtc = i;
        }
    }
    if (mCurrentInnerPlugin == UnknownIndex) {
        // Selected inner EAP type not found
        mCurrentInnerPlugin = DefaultIndex;
        mDefaultPluginInUse = true;      
    }
    
    mInnerEapType->setContentWidgetData("items", items);
    mInnerEapType->setContentWidgetData("currentIndex", mCurrentInnerPlugin);
    
    mForm->addConnection(mInnerEapType, SIGNAL(currentIndexChanged(int)), this,
        SLOT(innerEapTypeChanged(int)));
    
    mGroupItem->appendChild(mInnerEapType);
}

/*!
 * Adds validators.
 * 
 * @param modelIndex Model index
 */
void CpEapTlsMethodsUi::setValidator(const QModelIndex modelIndex)
{
    qDebug("CpEapTlsMethodsUi::itemActivated");

    HbDataFormViewItem *viewItem = qobject_cast<HbDataFormViewItem *>
        (mForm->itemByIndex(modelIndex));
    HbDataFormModelItem *modelItem = mModel->itemFromIndex(modelIndex);
    
    if (modelItem == mUsername) {
        // When username lineEdit is activated (shown) first time, validator is added
        mValidatorUsername.reset(mConfigIf->validatorEap(mPluginInfo.pluginHandle().type(),
            EapQtConfig::Username));
        HbLineEdit *edit = qobject_cast<HbLineEdit *> (viewItem->dataItemContentWidget());
        mValidatorUsername->updateEditor(edit);
    }
    else if (modelItem == mRealm) {
        // When realm lineEdit is activated (shown) first time, validator is added
        mValidatorRealm.reset(mConfigIf->validatorEap(mPluginInfo.pluginHandle().type(),
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
    if (mCurrentPeapVersion == PeapVersion1) {
        mInnerEapType->setContentWidgetData("currentIndex", mInnerEapGtc);
        mCurrentInnerPlugin = mInnerEapGtc;
    }
    else {
        mInnerEapType->setContentWidgetData("currentIndex", mInnerEapMschapv2);
        mCurrentInnerPlugin = mInnerEapMschapv2;
    }  
}

/*!
 * Stores the index of selected user certificate
 * 
 * @param value Index of selected certificate.
 */
void CpEapTlsMethodsUi::userCertChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::userCertChanged()");
    mCurrentUserCert = value;
}

/*!
 * Stores the index of selected authority certificate
 * 
 * @param value Index of selected certificate.
 */
void CpEapTlsMethodsUi::authorityCertChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::authorityCertChanged()");
    mCurrentAuthorityCert = value;
}

/*!
 * Stores the index of selected PEAP version
 * 
 * @param value Index of selected PEAP version.
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
 * @param value Index of selected ineer EAP type.
 */
void CpEapTlsMethodsUi::innerEapTypeChanged(int value)
{
    qDebug("CpEapTlsMethodsUi::innerEapTypeChanged()");
    mCurrentInnerPlugin = value;
}

/*!
 * Dims the username if generate username automatically has been selected.
 * 
 * @param state Tells is generate automatically checked.
 */
void CpEapTlsMethodsUi::usernameAutomaticChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::usernameAutomaticChanged");

    mUsername->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Dims the realm if generate realm automatically has been selected.
 * 
 * @param state Tells is generate automatically checked.
 */
void CpEapTlsMethodsUi::realmAutomaticChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::realmAutomaticChanged");

    mRealm->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Dims the authority certificate if select caCert automatically has been selected.
 * 
 * @param state Tells is select automatically checked.
 */
void CpEapTlsMethodsUi::authorityCertAutomaticChanged(int state)
{
    qDebug("CpEapTlsMethodsUi::authorityCertAutomaticChanged");

    mCaCert->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Converts check box state to boolean.
 * 
 * @param state Check box state
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
 * @param state Tells is check box checked.
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
        }
        else {
            qDebug("CpEapTlsMethodsUi::close - Store settings failed, prompt warning");
            // Store failed. Show error note to user
            QScopedPointer<HbMessageBox> infoBox;
            infoBox.reset(new HbMessageBox(
                HbMessageBox::MessageTypeWarning));
            infoBox->setText(hbTrId("txt_occ_info_unable_to_save_setting"));
            infoBox->clearActions();
            // Connect 'OK'-button to CpBaseSettingView 'aboutToClose'-signal
            HbAction *okAction = new HbAction(hbTrId("txt_common_button_ok"));
            infoBox->addAction(okAction);
            bool connected = connect(
                okAction,
                SIGNAL(triggered()),
                this,
                SIGNAL(aboutToClose()));
            Q_ASSERT(connected);
            infoBox->open();
            infoBox.take();
        }
    }
    else {
        qDebug("CpEapTlsMethodsUi::close - validation failed. Prompt question.");

        // Validate failed. Request user to exit anyway
        QScopedPointer<HbMessageBox> messageBox;
        messageBox.reset(new HbMessageBox(
            HbMessageBox::MessageTypeQuestion));
        messageBox->setAttribute(Qt::WA_DeleteOnClose);
        messageBox->setText(hbTrId("txt_occ_info_incomplete_details_return_without_sa"));
        messageBox->clearActions();
        // Connect 'YES'-button to CpBaseSettingView 'aboutToClose'-signal
        HbAction *okAction = new HbAction(hbTrId("txt_common_button_yes"));
        messageBox->addAction(okAction);
        bool connected = connect(
            okAction,
            SIGNAL(triggered()),
            this,
            SIGNAL(aboutToClose()));
        Q_ASSERT(connected);
        // Clicking 'NO'-button does nothing
        HbAction *cancelAction = new HbAction(hbTrId("txt_common_button_no"));
        messageBox->addAction(cancelAction);
        messageBox->setTimeout(HbPopup::NoTimeout);
        messageBox->open();
        messageBox.take();
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
    //true if select automatically is checked or certificate is selected
    if (mCaCertAutomatic->contentWidgetData("checkState") == Qt::Checked
        || mCurrentAuthorityCert > NotInUseIndex) {
        status = true;
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
 * @param eapConfig
 */
void CpEapTlsMethodsUi::setPeapVersion(EapQtConfig &eapConfig)
{
    qDebug("CpEapTlsMethodsUi::setPeapVersion()");
    if (mCurrentPeapVersion == PeapVersion0) {
        eapConfig.setValue(EapQtConfig::PeapVersion0Allowed, true);
        eapConfig.setValue(EapQtConfig::PeapVersion1Allowed, false);
    }
    else if (mCurrentPeapVersion == PeapVersion1) {
        eapConfig.setValue(EapQtConfig::PeapVersion0Allowed, false);
        eapConfig.setValue(EapQtConfig::PeapVersion1Allowed, true);            
    }
    else {
        Q_ASSERT(mCurrentPeapVersion == PeapVersionBoth);
        eapConfig.setValue(EapQtConfig::PeapVersion0Allowed, true);
        eapConfig.setValue(EapQtConfig::PeapVersion1Allowed, true);            
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
    eapConfig.setValue(EapQtConfig::OuterType, qVariantFromValue(mOuterHandle));
    eapConfig.setValue(EapQtConfig::UsernameAutomatic, checkStateToBool(
        mUsernameAutomatic->contentWidgetData("checkState").toInt()));
    eapConfig.setValue(EapQtConfig::Username, mUsername->contentWidgetData("text"));
    eapConfig.setValue(EapQtConfig::RealmAutomatic, checkStateToBool(
        mRealmAutomatic->contentWidgetData("checkState").toInt()));
    eapConfig.setValue(EapQtConfig::Realm, mRealm->contentWidgetData("text"));

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
        QList<QVariant> innerEaps;
        innerEaps.append(qVariantFromValue(mPlugins.at(mCurrentInnerPlugin).pluginHandle()));
        eapConfig.setValue(EapQtConfig::InnerType, innerEaps);
    }

    // Cipher suites
    qDebug("CpEapTlsMethodsUi::storeSettings - Cipher suites");
    eapConfig.setValue(EapQtConfig::CipherSuites, mGroupItemCs->ciphersuites());
    
    // PEAP version (valid only for PEAP)
    if (mPluginInfo.pluginHandle() == EapQtPluginHandle::PluginPeap) {
        setPeapVersion(eapConfig);
    }
    
    // Save configuration
    if (!mConfigIf->saveConfiguration(mPluginInfo.pluginHandle(), eapConfig)) {
        qDebug("CpEapTlsMethodsUi::storeSettings - configuration saving failed.");
        return false;
    }
    return true;
}

