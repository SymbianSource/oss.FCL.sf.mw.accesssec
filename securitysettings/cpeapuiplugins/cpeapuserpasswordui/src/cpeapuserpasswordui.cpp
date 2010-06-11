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
 *   Control Panel QT UI for username-password based EAP method configuration
 *
 */

/*
 * %version: 24 %
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
#include "cpeapuserpasswordui.h"

/*!
 * \class CpEapUserPasswordUi
 * \brief Implementes username-password based EAP method configuration ui. 
 */

// External function prototypes

// Local constants

/*! 
 * If password has already been stored into the database
 * user is shown dummy password (fixed number of asterisks)
 */
static const QVariant passwordExistString = "xxxx";

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
CpEapUserPasswordUi::CpEapUserPasswordUi(
    const EapQtConfigInterface::EapBearerType bearer,
    const int iapId,
    const EapQtPluginInfo &plugin, 
    const EapQtPluginHandle& outerHandle) :
        mConfigIf(new EapQtConfigInterface(bearer, iapId)),
        mPluginInfo(plugin), 
        mOuterHandle(outerHandle), 
        mForm(NULL),
        mModel(NULL), 
        mUsername(NULL), 
        mPasswordPrompt(NULL), 
        mPassword(NULL), 
        mValidatorUsername(NULL),
        mValidatorPassword(NULL), 
        mPasswordStored(false), 
        mPasswordChanged(false), 
        mPasswordEdit(NULL)
{
    qDebug("CpEapUserPasswordUi::CpEapUserPasswordUi");

    // IAP must be valid in construction (check includes
    // EapQtConfigInterface::IapIdUndefined)
    if (iapId < 0) {
        QT_THROW(std::bad_alloc());
        // scoped pointer gets deleted automaticaly on exception
    }

    initializeUserPasswordUi();
}

/*!
 * Destructor.
 */
CpEapUserPasswordUi::~CpEapUserPasswordUi()
{
    qDebug("CpEapUserPasswordUi::~CpEapUserPasswordUi");

    // mValidatorUsername, mValidatorPassword
    // mConfigIf: scoped pointer deleted automatically
}

/*!
 * Initializes the password-username ui and initializes objects based on configuration
 * read from the database.
 */
void CpEapUserPasswordUi::initializeUserPasswordUi()
{
    qDebug("CpEapUserPasswordUi::initializeUserPasswordUi");

    CpItemDataHelper itemDataHelper;

    // Read Configurations
    EapQtConfig eapConfig;
    bool configurationRead = mConfigIf->readConfiguration(mOuterHandle, mPluginInfo.pluginHandle(),
        eapConfig);
    if (!configurationRead) {
        qDebug("CpEapUserPasswordUi::initializeUserPasswordUi - read configuration failed.");
    }

    // Create UI objects and group 
    mForm = new HbDataForm();
    this->setWidget(mForm);
    
    mModel = new HbDataFormModel;

    HbDataFormModelItem *groupItem = new HbDataFormModelItem(HbDataFormModelItem::GroupItem,
        hbTrId("txt_occ_subhead_eap_module_settings").arg(mPluginInfo.localizationId()));
    mModel->appendDataFormItem(groupItem);

    // Connect signal to add validators when items get activated (visualization created).
    bool connected = connect(mForm, SIGNAL( itemShown(const QModelIndex&) ), this,
        SLOT( setValidator(const QModelIndex) ));
    Q_ASSERT(connected);
    
    // Username
    mUsername = new CpSettingFormItemData(HbDataFormModelItem::TextItem, hbTrId(
        "txt_occ_setlabel_username"));
    // Initialize the value from EapQtConfig
    mUsername->setContentWidgetData("text", eapConfig.value(EapQtConfig::Username));
    groupItem->appendChild(mUsername);

    // Password prompting
    mPasswordPrompt = new CpSettingFormItemData(HbDataFormModelItem::CheckBoxItem, hbTrId(
        "txt_occ_setlabel_password"));
    mPasswordPrompt->setContentWidgetData("text", hbTrId("txt_occ_setlabel_password_val_prompt"));
    mPasswordPrompt->setContentWidgetData("checkState", boolToCheckState(eapConfig.value(
        EapQtConfig::PasswordPrompt).toBool()));
    // Connect signal to disable/enable password when passwordPrompt changed 
    mForm->addConnection(mPasswordPrompt, SIGNAL(stateChanged(int)), this,
        SLOT(passwordPromptChanged(int)));
    groupItem->appendChild(mPasswordPrompt);

    // Password
    mPassword = new CpSettingFormItemData(HbDataFormModelItem::TextItem, hbTrId(
        "txt_occ_setlabel_password"));
    mPasswordStored = eapConfig.value(EapQtConfig::PasswordStored).toBool();
    // If password has already been stored into the databse
    // fixed number of asterisks are shown in UI
    if (mPasswordStored) {
        mPassword->setContentWidgetData("text", passwordExistString);
    }
    // Set password echo mode
    mPassword->setContentWidgetData("echoMode", HbLineEdit::Password);
    // Dimmed password if passwordPrompt is selected
    passwordPromptChanged(mPasswordPrompt->contentWidgetData("checkState") == Qt::Checked);
    // Connect signal to get info that user has changed the password
    mForm->addConnection(mPassword, SIGNAL(editingFinished()), this, SLOT(passwordChanged()));
    groupItem->appendChild(mPassword);

    // Set the model
    mForm->setModel(mModel);
    itemDataHelper.bindToForm(mForm);

    // Expand userpasswordui settings group
    mForm->setExpanded(mModel->indexFromItem(groupItem), TRUE);
}

/*!
 * Adds validators and connects focusIn event to the Password.
 * 
 * @param modelIndex Model index
 */
void CpEapUserPasswordUi::setValidator(const QModelIndex modelIndex)
{
    qDebug("CpEapUserPasswordUi::itemActivated");

    HbDataFormViewItem *viewItem = qobject_cast<HbDataFormViewItem *>
        (mForm->itemByIndex(modelIndex));
    HbDataFormModelItem *modelItem = mModel->itemFromIndex(modelIndex);
    
    if (modelItem == mUsername) {
        // When username lineEdit is activated (shown) first time, validator is added
        mValidatorUsername.reset(mConfigIf->validatorEap(mPluginInfo.pluginHandle().type(),
            EapQtConfig::Username));
        HbLineEdit *usernameEdit = qobject_cast<HbLineEdit *> (viewItem->dataItemContentWidget());
        mValidatorUsername->updateEditor(usernameEdit);
    }
    else if (modelItem == mPassword) {
        // When password lineEdit is activated (shown) first time, validator is added
        mValidatorPassword.reset(mConfigIf->validatorEap(mPluginInfo.pluginHandle().type(),
            EapQtConfig::Password));
        mPasswordEdit = qobject_cast<HbLineEdit *> (viewItem->dataItemContentWidget());
        mValidatorPassword->updateEditor(mPasswordEdit);
        // Install event filter to clear dummy password, when password is started to edit.
        mPasswordEdit->installEventFilter(this);
    }
}

/*!
 * This is called when user is about to exit the view.
 * Validates configuration and saves settings.
 * If configuration is not valid prompts question dialog.
 * If user chooses "OK" leaves without saving.
 * 
 */
void CpEapUserPasswordUi::close()
{
    qDebug("CpEapUserPasswordUi::close");
    if (validate()) {
        qDebug("CpEapUserPasswordUi::close - Store settings");
        storeSettings();
        qDebug("CpEapUserPasswordUi::close - Settings stored, exit");
        CpBaseSettingView::close();
    }
    else {
        qDebug("CpEapUserPasswordUi::close - validation failed. Prompt question.");
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
 * Converts check box state to boolean.
 * 
 * @param state Check box state
 * 
 * @return true if Check box is checked, false otherwise.
 */
bool CpEapUserPasswordUi::checkStateToBool(const int state)
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
int CpEapUserPasswordUi::boolToCheckState(const bool state)
{
    return (false == state ? Qt::Unchecked : Qt::Checked);
}

/*!
 * Dims the password if passwordPrompt has been selected.
 * 
 * @param state Tells is password prompt checked.
 */
void CpEapUserPasswordUi::passwordPromptChanged(int state)
{
    qDebug("CpEapUserPasswordUi::passwordPromptChanged - state: %d", state);

    mPassword->setContentWidgetData("enabled", !checkStateToBool(state));
}

/*!
 * Saves information that password has been changed and must be stored.
 * If the new password is not given, the stored password is kept (if exists).
 */
void CpEapUserPasswordUi::passwordChanged()
{
    if (mPassword->contentWidgetData("text") != "") {
        // Stored password is considered as changed only if user
        // gives new unempty password
        qDebug("CpEapUserPasswordUi::passwordChanged");
        mPasswordChanged = true;
    }
}

/*!
 * When a focus moves into the password editor, possible dummy password is cleared.
 */
bool CpEapUserPasswordUi::eventFilter(QObject *obj, QEvent *event)
{
    
    if (obj == mPasswordEdit && event->type() == QEvent::FocusIn 
        && mPasswordStored && !mPasswordChanged) {
        qDebug("CpEapUserPasswordUi::eventFilter - mPasswordEdit and FocusIn");
        mPassword->setContentWidgetData("text", "");
    }
    return false;
}

/*!
 * Validates settings configuration.
 * 
 * @return true if configuration OK, false otherwise.
 */
bool CpEapUserPasswordUi::validate()
{
    qDebug("CpEapUserPasswordUi::validate");
    bool valid = false;

    if ((EapQtValidator::StatusOk == mValidatorUsername->validate(mUsername->contentWidgetData(
        "text"))) && validatePasswordGroup()) {
        qDebug("CpEapUserPasswordUi::validate - OK");
        valid = true;
    }

    return valid;
}

/*!
 * Validates password and passwordPrompt.
 * 
 * @return true if OK, false otherwise.
 */
bool CpEapUserPasswordUi::validatePasswordGroup()
{
    qDebug("CpEapUserPasswordUi::validatePasswordGroup");
    bool status = false;
    // true if password prompt is checked, stored password has not changed
    // or changed/given passrword is valid
    if (mPasswordPrompt->contentWidgetData("checkState") == Qt::Checked 
        || (mPasswordStored && !mPasswordChanged) 
        || (mPasswordStored && mPasswordChanged && EapQtValidator::StatusOk
            == mValidatorPassword->validate(mPassword->contentWidgetData("text").toString()))
        || (!mPasswordStored && EapQtValidator::StatusOk
            == mValidatorPassword->validate(mPassword->contentWidgetData("text").toString()))) {
        qDebug("CpEapUserPasswordUi::validatePasswordGroup - OK");
        status = true;
    }
    return status;
}

/*!
 * Stores settings given via username-password configuration UI
 */
void CpEapUserPasswordUi::storeSettings()
{
    qDebug("CpEapUserPasswordUi::storeSettings");

    EapQtConfig eapConfig;

    eapConfig.setValue(EapQtConfig::OuterType, qVariantFromValue(mOuterHandle));
    eapConfig.setValue(EapQtConfig::Username, mUsername->contentWidgetData("text"));
    eapConfig.setValue(EapQtConfig::PasswordPrompt, checkStateToBool(
        mPasswordPrompt->contentWidgetData("checkState").toInt()));
    if (mPasswordPrompt->contentWidgetData("checkState") == Qt::Checked) {
        if(mPasswordStored) {
            // Stored password is cleared if prompting has been enabled
            eapConfig.setValue(EapQtConfig::PasswordClear, true);
            eapConfig.setValue(EapQtConfig::Password, "");
        }
        // else do nothing (password is not saved)
    }
    else {
        // Password prompt is disabled
        if (!mPasswordChanged && mPasswordStored) {
            // Stored password has not been changed
            eapConfig.setValue(EapQtConfig::PasswordStored, true);
        }
        else if (mPasswordChanged || !mPasswordStored) {
            // Store the new password
            eapConfig.setValue(EapQtConfig::Password, mPassword->contentWidgetData("text").toString());
        }
    }
    
    if (!mConfigIf->saveConfiguration(mPluginInfo.pluginHandle(), eapConfig)) {
        qDebug("CpEapUserPasswordUi::storeSettings - configuration saving failed.");
    }
}
