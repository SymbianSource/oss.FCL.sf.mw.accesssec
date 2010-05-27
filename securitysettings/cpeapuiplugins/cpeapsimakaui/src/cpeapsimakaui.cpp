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
 *   Control Panel QT UI for EAP-SIM and EAP-AKA method configuration
 *
 */

/*
 * %version:  16 %
 */

// System includes
#include <HbDataForm>
#include <HbDataFormModel>
#include <HbDataFormViewItem>
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
        mConfigIf(new EapQtConfigInterface(bearer, iapId)),
        mPluginInfo(plugin),
        mOuterHandle(outerHandle),
        mForm(NULL),
        mModel(NULL),
        mUsernameAutomatic(NULL),
        mUsername(NULL),
        mRealmAutomatic(NULL),
        mRealm(NULL),
        mValidatorRealm(NULL),
        mValidatorUsername(NULL)
{
    qDebug("CpEapSimAkaUi::CpEapSimAkaUi");

    // IAP must be valid in construction (check includes
    // EapQtConfigInterface::IapIdUndefined)
    if (iapId < 0) {
        QT_THROW(std::bad_alloc());
        // scoped pointer gets deleted automaticaly on exception
    }

    initializeSimAkaUi();
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
 * Initializes the sim-aka ui and initializes objects based on configuration
 * read from the database.
 */
void CpEapSimAkaUi::initializeSimAkaUi()
{
    qDebug("CpEapSimAkaUi::initializeSimAkaUi");

    CpItemDataHelper itemDataHelper;

    // Read Configurations
    EapQtConfig eapConfig;
    bool configurationRead = mConfigIf->readConfiguration(mOuterHandle, mPluginInfo.pluginHandle(),
        eapConfig);
    if (!configurationRead) {
        qDebug("CpEapSimAkaUi::initializeSimAkaUi - read configuration failed.");
    }
    
    // Create UI objects and group 
    mForm = new HbDataForm();
    this->setWidget(mForm);
    
    mModel = new HbDataFormModel(mForm);
    HbDataFormModelItem *groupItem = new HbDataFormModelItem(HbDataFormModelItem::GroupItem,
        hbTrId("txt_occ_subhead_eap_module_settings").arg(mPluginInfo.localizationId()));
    mModel->appendDataFormItem(groupItem);

    // Connect signal to add validators when items get activated (visualization created).
    bool connected = connect(mForm, SIGNAL( itemShown(const QModelIndex&) ), this,
        SLOT( setValidator(const QModelIndex) ));
    Q_ASSERT(connected);

    // UsernameAutomatic
    mUsernameAutomatic = new CpSettingFormItemData(HbDataFormModelItem::CheckBoxItem, hbTrId(
        "txt_occ_setlabel_user_name"));
    mUsernameAutomatic->setContentWidgetData("text", hbTrId(
        "txt_occ_setlabel_user_name_val_generate_automatica"));
    // Initialize the value from EapQtConfig
    // Generate username automatically is selected by default
    mUsernameAutomatic->setContentWidgetData("checkState", boolToCheckState(eapConfig.value(
        EapQtConfig::UsernameAutomatic).toBool()));
    // Connect signal to disable/enable username when usernameAutomatic changed   
    mForm->addConnection(mUsernameAutomatic, SIGNAL(stateChanged(int)), this,
        SLOT(usernameAutomaticChanged(int)));
    groupItem->appendChild(mUsernameAutomatic);

    //Username
    mUsername = new CpSettingFormItemData(HbDataFormModelItem::TextItem, hbTrId(
        "txt_occ_setlabel_user_name"));
    mUsername->setContentWidgetData("text", eapConfig.value(EapQtConfig::Username));
    // Dimmed username if usernameAutomatic selected
    usernameAutomaticChanged(mUsernameAutomatic->contentWidgetData("checkState") == Qt::Checked);
    groupItem->appendChild(mUsername);

    // RealmAutomatic
    mRealmAutomatic = new CpSettingFormItemData(HbDataFormModelItem::CheckBoxItem, hbTrId(
        "txt_occ_setlabel_realm"));
    mRealmAutomatic->setContentWidgetData("text", hbTrId(
        "txt_occ_setlabel_realm_val_generate_automatically"));
    // Initialize the value from EapQtConfig
    // Generate realm automatically is selected by default
    mRealmAutomatic->setContentWidgetData("checkState", boolToCheckState(eapConfig.value(
        EapQtConfig::RealmAutomatic).toBool()));
    // connect signal to disable/enable realm when realmAutomatic changed 
    mForm->addConnection(mRealmAutomatic, SIGNAL(stateChanged(int)), this,
        SLOT(realmAutomaticChanged(int)));
    groupItem->appendChild(mRealmAutomatic);

    //Realm
    mRealm = new CpSettingFormItemData(HbDataFormModelItem::TextItem, hbTrId(
        "txt_occ_setlabel_realm"));
    mRealm->setContentWidgetData("text", eapConfig.value(EapQtConfig::Realm));
    // Dimmed realm if realmAutomatic selected
    realmAutomaticChanged(mRealmAutomatic->contentWidgetData("checkState") == Qt::Checked);
    groupItem->appendChild(mRealm);

    // Set the model
    itemDataHelper.bindToForm(mForm);
    mForm->setModel(mModel);

    // Expand simakaui settings group
    mForm->setExpanded(mModel->indexFromItem(groupItem), TRUE);
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
 * This is called when user is about to exit the view.
 * Validates configuration and saves settings.
 * If configuration is not valid prompts question dialog.
 * If user chooses "OK" leaves without saving.
 * 
 */
void CpEapSimAkaUi::close()
{
    qDebug("CpEapSimAkaUi::close");
    if (validate()) {
        qDebug("CpEapSimAkaUi::close - Store settings and exit");
        storeSettings();
        CpBaseSettingView::close();
    }
    else {
        qDebug("CpEapSimAkaUi::close - validation failed. Prompt question.");
        HbMessageBox *note = new HbMessageBox(HbMessageBox::MessageTypeQuestion);
        note->setAttribute(Qt::WA_DeleteOnClose);
        note->setText(hbTrId("txt_occ_info_incomplete_details_return_without_sa"));
        note->clearActions();
        // Connect 'YES'-button to CpBaseSettingView 'aboutToClose'-signal
        HbAction *okAction = new HbAction(hbTrId("txt_common_button_yes"));
        note->addAction(okAction);
        bool connected = connect(
            okAction,
            SIGNAL(triggered()),
            this,
            SIGNAL(aboutToClose()));
        Q_ASSERT(connected);
        // Clicking 'NO'-button does nothing
        HbAction *cancelAction = new HbAction(hbTrId("txt_common_button_no"));
        note->addAction(cancelAction);
        note->setTimeout(HbPopup::NoTimeout);
        note->open();
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
 */
void CpEapSimAkaUi::storeSettings()
{
    qDebug("CpEapSimAkaUi::storeSettings");

    EapQtConfig eapConfig;

    eapConfig.setValue(EapQtConfig::OuterType, qVariantFromValue(mOuterHandle));
    eapConfig.setValue(EapQtConfig::UsernameAutomatic, checkStateToBool(
        mUsernameAutomatic->contentWidgetData("checkState").toInt()));
    eapConfig.setValue(EapQtConfig::Username, mUsername->contentWidgetData("text"));
    eapConfig.setValue(EapQtConfig::RealmAutomatic, checkStateToBool(
        mRealmAutomatic->contentWidgetData("checkState").toInt()));
    eapConfig.setValue(EapQtConfig::Realm, mRealm->contentWidgetData("text"));

    if (!mConfigIf->saveConfiguration(mPluginInfo.pluginHandle(), eapConfig)) {
        qDebug("CpEapSimAkaUi::storeSettings - configuration saving failed.");
    }
}
