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
 *   Control Panel QT UI for EAP-SIM and EAP-AKA method configuration
 *
 */

/*
 * %version:  20 %
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

// User includes
#include "cpeapsimakaui.h"

/*!
 * \class CpEapSimAkaUi
 * \brief Implementes EAP-SIM and EAP-AKA method configuration ui. 
 */

// External function prototypes

// Local constants

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
CpEapSimAkaUi::CpEapSimAkaUi(
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
        mValidatorRealm(NULL),
        mValidatorUsername(NULL)
{
    qDebug("CpEapSimAkaUi::CpEapSimAkaUi");

    setObjectName("CpEapSimAkaUi");
    // IAP must be valid in construction (check includes
    // EapQtConfigInterface::IapIdUndefined)
    if (iapId < 0) {
        QT_THROW(std::bad_alloc());
        // scoped pointer gets deleted automaticaly on exception
    }

    // Get EAP config interface
    mConfigIf.reset(new EapQtConfigInterface(bearer, iapId));
    
    createUi();
}

/*!
 * Destructor.
 */
CpEapSimAkaUi::~CpEapSimAkaUi()
{
    qDebug("CpEapSimAkaUi::~CpEapSimAkaUi");

    // mValidatorRealm, mValidatorUsername
    // mConfigIf: scoped pointer deleted automatically
}

/*!
 * Creates EAP-SIM/AKA UI and initilizes settings read via
 * EapQtConfigInterface
 */
void CpEapSimAkaUi::createUi()
{
    qDebug("CpEapSimAkaUi::createUi");

    // Read EAP Configurations
    bool configurationRead = mConfigIf->readConfiguration(mOuterHandle, mPluginInfo.pluginHandle(),
        mEapConfig);
    if (!configurationRead) {
        qDebug("CpEapSimAkaUi::initializeSimAkaUi - read configuration failed.");
    }
    
    // Construct EAP-SIM/AKA settings UI 
    mForm = new HbDataForm();
    mForm->setObjectName("CpEapSimAkaUiForm");
    this->setWidget(mForm);
    
    mModel = new HbDataFormModel(mForm);
    mModel->setObjectName("CpEapSimAkaUiModel");
    
    mGroupItem = new HbDataFormModelItem(
        HbDataFormModelItem::GroupItem,
        HbParameterLengthLimiter(
            "txt_occ_subhead_eap_module_settings").arg(
                mPluginInfo.localizationId()));
    
    mGroupItem->setContentWidgetData("objectName", "CpEapSimAkaUiGroupItem");
    
    mModel->appendDataFormItem(mGroupItem);

    // The parameter given as 0 is a HbDataForm pointer, not parent
    mItemDataHelper = new CpItemDataHelper(0);
    mItemDataHelper->setParent(this);

    // Create UI components
    createUsername();
    createRealm();
    
    mItemDataHelper->bindToForm(mForm);
    mForm->setModel(mModel);
    
    // Connect signal to add validators when items get activated (visualization created).
    bool connected = connect(
        mForm, 
        SIGNAL( itemShown(const QModelIndex&) ), 
        this,
        SLOT( setValidator(const QModelIndex) ));
    Q_ASSERT(connected);

    // Expand EAP-SIM/AKA settings group
    mForm->setExpanded(mModel->indexFromItem(mGroupItem), true);
}

/*!
 * Creates Username group:
 * Generate automatically checkBox and username lineEdit
 */
void CpEapSimAkaUi::createUsername()
{
    qDebug("CpEapSimAkaUi::createUsername()");
    // UsernameAutomatic
    mUsernameAutomatic = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_user_name"));
    
    mUsernameAutomatic->setContentWidgetData("objectName", "CpEapSimAkaUiUsernameAutomatic");
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
        mUsernameAutomatic, SIGNAL(stateChanged(int)), 
        this, SLOT(usernameAutomaticChanged(int)));
    
    mGroupItem->appendChild(mUsernameAutomatic);

    //Username
    mUsername = new CpSettingFormItemData(
        HbDataFormModelItem::TextItem, 
        hbTrId("txt_occ_setlabel_user_name"));
    
    mUsername->setContentWidgetData("objectName", "CpEapSimAkaUiUsername");
    mUsername->setContentWidgetData("text", mEapConfig.value(EapQtConfig::Username));
    
    // Dim username if usernameAutomatic selected
    usernameAutomaticChanged(mUsernameAutomatic->contentWidgetData("checkState") == Qt::Checked);
    mGroupItem->appendChild(mUsername);
}

/*!
 * Creates Realm group:
 * Generate automatically checkBox and realm lineEdit
 */
void CpEapSimAkaUi::createRealm()
{
    qDebug("CpEapSimAkaUi::createRealm()");
    // RealmAutomatic
    mRealmAutomatic = new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, 
        hbTrId("txt_occ_setlabel_realm"));
    
    mRealmAutomatic->setContentWidgetData("objectName", "CpEapSimAkaUiRealmAutomatic");
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
    
    mGroupItem->appendChild(mRealmAutomatic);

    //Realm
    mRealm = new CpSettingFormItemData(
        HbDataFormModelItem::TextItem, 
        hbTrId("txt_occ_setlabel_realm"));
    
    mRealm->setContentWidgetData("objectName", "CpEapSimAkaUiRealm");
    mRealm->setContentWidgetData("text", mEapConfig.value(EapQtConfig::Realm));
    
    // Dim realm if realmAutomatic selected
    realmAutomaticChanged(mRealmAutomatic->contentWidgetData("checkState") == Qt::Checked);
    mGroupItem->appendChild(mRealm);
}

/*!
 * Adds validators.
 * 
 * @param modelIndex Model index
 */
void CpEapSimAkaUi::setValidator(const QModelIndex modelIndex)
{
    qDebug("CpEapUserPasswordUi::itemActivated");

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
    }
    else if (modelItem == mRealm) {
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
 * This is called when user is about to exit the view.
 * Validates configuration and saves settings.
 * If configuration is not valid prompts question dialog.
 * If user chooses "OK" leaves without saving.
 * 
 */
void CpEapSimAkaUi::close()
{
    qDebug("CpEapSimAkaUi::close");

    // Validate configuration
    if (validate()) {
        qDebug("CpEapSimAkaUi::close - Validation OK");

        // Store settings
        if (storeSettings()){
            qDebug("CpEapSimAkaUi::close - Settings stored, close view");
            // Close view
            CpBaseSettingView::close();   
        }
        else {
            qDebug("CpEapSimAkaUi::close - Store settings failed, prompt warning");
            // Store failed. Show error note to user
            QScopedPointer<HbMessageBox> infoBox;
            infoBox.reset(new HbMessageBox(HbMessageBox::MessageTypeWarning));
            infoBox->setObjectName("CpEapSimAkaUiMessageBoxFailed");
            infoBox->setAttribute(Qt::WA_DeleteOnClose);
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
        qDebug("CpEapSimAkaUi::close - validation failed. Prompt question.");
        QScopedPointer<HbMessageBox> messageBox;
        messageBox.reset(new HbMessageBox(HbMessageBox::MessageTypeQuestion));
        messageBox->setObjectName("CpEapSimAkaUiMessageBoxValidationFailed");
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
 * Dims the realm if generate realm automatically has been selected.
 * 
 * @param state Tells is generate automatically checked.
 */
void CpEapSimAkaUi::realmAutomaticChanged(int state)
{
    qDebug("CpEapSimAkaUi::realmAutomaticChanged");

    mRealm->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Dims the username if generate username automatically has been selected.
 * 
 * @param state Tells is generate automatically checked.
 */
void CpEapSimAkaUi::usernameAutomaticChanged(int state)
{
    qDebug("CpEapSimAkaUi::usernameAutomaticChanged");

    mUsername->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Converts check box state to boolean.
 * 
 * @param state Check box state
 * 
 * @return true if Check box is checked, false otherwise.
 */
bool CpEapSimAkaUi::checkStateToBool(const int state)
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
int CpEapSimAkaUi::boolToCheckState(const bool state)
{
    return (false == state ? Qt::Unchecked : Qt::Checked);
}

/*!
 * Validates settings configuration.
 * 
 * @return true if configuration OK, false otherwise.
 */
bool CpEapSimAkaUi::validate()
{
    bool valid = false;

    if (validateGroup(mUsername, mUsernameAutomatic, mValidatorUsername.data()) 
        && validateGroup(mRealm, mRealmAutomatic, mValidatorRealm.data())) {
        valid = true;
    }

    return valid;
}

/*!
 * Validates checkBox and lineEdit group.
 * 
 * @return true if OK, false otherwise.
 */
bool CpEapSimAkaUi::validateGroup(CpSettingFormItemData *edit, CpSettingFormItemData *checkBox,
    EapQtValidator *validator)
{
    bool status = false;
    // true if generate automatically is checked or given value is valid
    if (checkBox->contentWidgetData("checkState") == Qt::Checked
        || EapQtValidator::StatusOk == validator->validate(
            edit->contentWidgetData("text"))) {
        status = true;
    }
    return status;
}

/*!
 * Stores settings given via SIM-AKA configuration UI
 * 
 * @return false if saving failed, true otherwise
 */
bool CpEapSimAkaUi::storeSettings()
{
    qDebug("CpEapSimAkaUi::storeSettings");

    EapQtConfig eapConfig;

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

    // Save configuration
    if (!mConfigIf->saveConfiguration(mPluginInfo.pluginHandle(), eapConfig)) {
        qDebug("CpEapSimAkaUi::storeSettings - configuration saving failed.");
        return false;
    }
    return true;
}
