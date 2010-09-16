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
 *   Control Panel QT UI for PAC store configuration
 *
 */

/*
 * %version: 6 %
 */

// System includes
#include <HbMessageBox>
#include <HbInputDialog>
#include <HbAction>
#include <HbLineEdit>
#include <cpsettingformitemdata.h>
#include <cpitemdatahelper.h>
#include <eapqtvalidator.h>
#include <eapqtpacstoreconfig.h>

// User includes
#include "cpeaptlsmethodsui.h"
#include "cpeappacstoreui.h"

/*!
 * \class CpEapPacStoreUi
 * \brief Implementes PAC Store configuration group. 
 */

// External function prototypes

// Local constants

/*!
 * First lineEdit of the dialog
 */
static const int FirstRow = 0;
/*
 * Second lineEdit of the dialog
 */
static const int SecondRow = 1;

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in] configIf  Pointer to EapQtConfigInterface
 */

CpEapPacStoreUi::CpEapPacStoreUi(EapQtConfigInterface *configIf) :
        mConfigIf(configIf),
        mItemDataHelper(NULL),
        mPacStoreGroup(NULL),
        mPacStorePassword(NULL),
        mResetPacStore(NULL),
        mPacStorePasswordState(0),
        mExistPasswordDialog(NULL),
        mNewPasswordDialog(NULL),
        mMessageBox(NULL)
{
    qDebug("CpEapPacStoreUi::CpEapPacStoreUi()");
}

/*!
 * Destructor.
 */
CpEapPacStoreUi::~CpEapPacStoreUi()
{
    qDebug("CpEapPacStoreUi::~CpEapPacStoreUi()");

}

/*!
 * Returns PAC store UI group
 * 
 * @param [in] dataHelper  CpItemDataHelper to add Connections
 * 
 * @return PAC store group
 */
CpSettingFormItemData* CpEapPacStoreUi::uiInstance(
    CpItemDataHelper &dataHelpper)
{
    //Store the address of the Data Helper
    mItemDataHelper = &dataHelpper;
    
    mPacStoreGroup.reset(new CpSettingFormItemData(
        HbDataFormModelItem::GroupItem, 
        hbTrId("txt_occ_subhead_pac_store")));
    mPacStoreGroup->setContentWidgetData("objectName", "CpEapPacStoreUiGroupItem");
    
    // Read PAC Store configuration
    bool configurationRead = mConfigIf->readPacStoreConfiguration(
        mPacStoreConfig);
    if (!configurationRead) {
        // Use default value - PAC store password prompt
        qDebug("CpEapPacStoreUi::uiInstance - read PAC store configuration failed.");
    }
    
    // Create PAC store password selection comboBox
    createPacStorePassword();
    
    // Create Reset PAC store button
    createResetPacStore();

    return mPacStoreGroup.take();
}

/*!
 * Creates PAC store password selection comboBox
 */
void CpEapPacStoreUi::createPacStorePassword()
{
    qDebug("CpEapPacStoreUi::createPacStorePassword()");
    // Create PAC store password comboBox
    mPacStorePassword = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, 
        hbTrId("txt_occ_setlabel_pac_store_password"));
    mPacStoreGroup->appendChild(mPacStorePassword);
    mPacStorePassword->setContentWidgetData(
        "objectName", 
        "CpEapPacStoreUiPassword");
    
    // Add items to comboBox List
    QStringList items;
    items << hbTrId("txt_occ_setlabel_pac_store_password_val_prompt")
        << hbTrId("txt_occ_setlabel_pac_store_password_val_user_defin");
    mPacStorePassword->setContentWidgetData("items", items);
    
    // Initialize selection from PAC store configuration
    if (mPacStoreConfig.value(EapQtPacStoreConfig::PacStoreState).toInt() 
        == EapQtPacStoreConfig::PacStoreStatePasswordStored) {
        mPacStorePassword->setContentWidgetData("currentIndex", PacStorePasswordUserDefined);
        mPacStorePasswordState = PacStorePasswordUserDefined;
    } else {
        mPacStorePassword->setContentWidgetData("currentIndex", PacStorePasswordPrompt);
        mPacStorePasswordState = PacStorePasswordPrompt;
    }
    
    // Connect signal for password state changed
    mItemDataHelper->addConnection(mPacStorePassword, SIGNAL(currentIndexChanged(int)), this,
        SLOT(pacStorePasswordChanged(int)));
}

/*!
 * Creates reset PAC store button
 */
void CpEapPacStoreUi::createResetPacStore()
{
    qDebug("CpEapPacStoreUi::createResetPacStore()");
    
    // Create button
    mResetPacStore = new CpSettingFormItemData(
        HbDataFormModelItem::ToggleValueItem,
        hbTrId(""));
    mPacStoreGroup->appendChild(mResetPacStore);
    mResetPacStore->setContentWidgetData(
        "objectName", 
        "CpEapPacStoreUiResetPacStore");    

    // Define text for the button
    mResetPacStore->setContentWidgetData("text",
            hbTrId("txt_occ_button_reset_pac_store"));
    mResetPacStore->setContentWidgetData("additionalText", 
            hbTrId("txt_occ_button_reset_pac_store"));

    // Connect signal for button pressed
    mItemDataHelper->addConnection(
        mResetPacStore, 
        SIGNAL(valueChanged(QPersistentModelIndex, QVariant)), 
        this,
        SLOT(resetPacStoreButtonPressed(QPersistentModelIndex, QVariant)));
}

/*!
 * Set PAC store password state.
 * This is called when state changed has failed and state shall be restored. 
 * 
 * @param [in] state  Pac store password state: Prompt/Userd defined.
 */
void CpEapPacStoreUi::setPacStorePasswordState(const PacStorePasswordIndexes state)
{
    // Remove signal connection while state is restored
    mItemDataHelper->removeConnection(mPacStorePassword, SIGNAL(currentIndexChanged(int)), this,
        SLOT(pacStorePasswordChanged(int)));
    mPacStorePassword->setContentWidgetData("currentIndex", state);
    // Restore connection
    mItemDataHelper->addConnection(mPacStorePassword, SIGNAL(currentIndexChanged(int)), this,
        SLOT(pacStorePasswordChanged(int)));
    mPacStorePasswordState = state;
}

/*!
 * Show PAC store password query when PAC store already exists
 */
void CpEapPacStoreUi::showExistPasswordQuery()
{
    qDebug("CpEapPacStoreUi::showExistPasswordQuery()");
    
    // Create dialog
    QScopedPointer<HbInputDialog> existPasswordDialog(new HbInputDialog());
    existPasswordDialog->setObjectName("CpEapPacStoreUiExistPasswordDialog");
    existPasswordDialog->setAttribute(Qt::WA_DeleteOnClose);
    existPasswordDialog->setPromptText(hbTrId("txt_occ_dialog_pac_store_password"));
    existPasswordDialog->setInputMode(HbInputDialog::TextInput);

    // Add validator
    mValidatorPacStore.reset( 
        mConfigIf->validatorPacStore(
            EapQtPacStoreConfig::PacStorePasswordConfirmation));
    Q_ASSERT(mValidatorPacStore.data());
    mValidatorPacStore->updateEditor(existPasswordDialog->lineEdit());

    // Set Password echo mode
    existPasswordDialog->setEchoMode(HbLineEdit::Password);
    
    // Configurate buttons
    existPasswordDialog->clearActions();
    HbAction *okAction = new HbAction(
        hbTrId("txt_common_button_ok"),
        existPasswordDialog.data());
    existPasswordDialog->addAction(okAction);
    okAction->setObjectName("CpEapPacStoreUiExistPasswordDialogOkAction");
    bool connected = connect(okAction, 
                             SIGNAL(triggered()), 
                             this, 
                             SLOT(completeExistPasswordQuery()));
    Q_ASSERT(connected);
    HbAction *cancelAction = new HbAction(
        hbTrId("txt_common_button_cancel"),
        existPasswordDialog.data());
    existPasswordDialog->addAction(cancelAction);
    cancelAction->setObjectName("CpEapPacStoreUiExistPasswordDialogCancelAction");
    connected = connect(cancelAction, 
                        SIGNAL(triggered()), 
                        this, 
                        SLOT(cancelPasswordQuery()));
    Q_ASSERT(connected);

    // Take the ownership of the dialog from QScopedPointer
    mExistPasswordDialog = existPasswordDialog.take();
    
    // Show dialog
    mExistPasswordDialog->show();
}

/*!
 * Show create PAC store password query when no PAC store exists
 */
void CpEapPacStoreUi::showNewPasswordQuery()
{
    qDebug("CpEapPacStoreUi::showNewPasswordQuery()");

    // Create dialog
    QScopedPointer<HbInputDialog> newPasswordDialog(new HbInputDialog());
    newPasswordDialog->setObjectName("CpEapPacStoreUiNewPasswordDialog");
    newPasswordDialog->setAttribute(Qt::WA_DeleteOnClose);
    newPasswordDialog->setAdditionalRowVisible(true);
    newPasswordDialog->setPromptText(
        hbTrId("txt_occ_dialog_create_password_for_encrypted_pac_s"), 
        FirstRow);
    newPasswordDialog->setPromptText(
        hbTrId("txt_occ_dialog_verify_password"),
        SecondRow);
    newPasswordDialog->setInputMode(HbInputDialog::TextInput);
    
    // Add validators
    mValidatorPacStore.reset( 
        mConfigIf->validatorPacStore(
            EapQtPacStoreConfig::PacStorePassword));
    Q_ASSERT(mValidatorPacStore.data());
    mValidatorPacStore->updateEditor(newPasswordDialog->lineEdit(FirstRow));
    mValidatorPacStore->updateEditor(newPasswordDialog->lineEdit(SecondRow));

    // Set Password echo mode
    newPasswordDialog->setEchoMode(HbLineEdit::Password, FirstRow);
    newPasswordDialog->setEchoMode(HbLineEdit::Password, SecondRow);
    
    // Configure buttons
    newPasswordDialog->clearActions();
    HbAction *okAction = new HbAction(
        hbTrId("txt_common_button_ok"),
        newPasswordDialog.data());
    newPasswordDialog->addAction(okAction);
    okAction->setObjectName("CpEapPacStoreUiNewPasswordDialogOkAction");
    bool connected = connect(okAction, 
                             SIGNAL(triggered()), 
                             this, 
                             SLOT(completeNewPasswordQuery()));
    Q_ASSERT(connected);
    HbAction *cancelAction = new HbAction(
        hbTrId("txt_common_button_cancel"),
        newPasswordDialog.data());
    newPasswordDialog->addAction(cancelAction);
    cancelAction->setObjectName("CpEapPacStoreUiNewPasswordDialogCancelAction");
    connected = connect(cancelAction, 
                        SIGNAL(triggered()), 
                        this, 
                        SLOT(cancelPasswordQuery()));
    
    // Take the ownership of the dialog from QScopedPointer
    mNewPasswordDialog = newPasswordDialog.take();
    
    // Show dialog
    mNewPasswordDialog->show();
}

/*!
 * Shows message box with "OK" button using given text.
 * 
 * @param [in] type  Message box type
 * @param [in] text  Text to be shown
 */
void CpEapPacStoreUi::showMessageBox(
    HbMessageBox::MessageBoxType type,
    const QString &text)
{
    // Create a message box
    mMessageBox = QSharedPointer<HbMessageBox>(new HbMessageBox(type));
    mMessageBox->setObjectName("CpEapPacStoreUiMessageBox");
    mMessageBox->setText(text);
    mMessageBox->setModal(true);
    mMessageBox->setTimeout(HbPopup::NoTimeout);
    mMessageBox->open();
}

/*!
 * This slot is called when PAC Store password state has been changed
 * 
 * @param [in] value  New state of password (prompt/user defined)
 */
void CpEapPacStoreUi::pacStorePasswordChanged(int value)
{
    qDebug("CpEapPacStoreUi::pacStorePasswordChanged()");

    if (mPacStorePasswordState != value) {
        // Value is really changed
        if (value == PacStorePasswordPrompt) {
            // Prompt
            qDebug("CpEapPacStoreUi::pacStorePasswordChanged - Prompt");
            
            //Show message box to confirm the PAC store password clearing
            HbMessageBox *questionBox = new HbMessageBox(HbMessageBox::MessageTypeQuestion);
            questionBox->setObjectName("CpEapPacStoreUiClearPasswordQuestion");
            questionBox->setText(hbTrId("txt_occ_info_pac_store_password_will_no_longer_be"));
            questionBox->setModal(true);
            questionBox->setTimeout(HbPopup::NoTimeout);
            questionBox->setAttribute(Qt::WA_DeleteOnClose);
            questionBox->setStandardButtons(HbMessageBox::Yes | HbMessageBox::No);
            questionBox->open(this,SLOT(clearPacStorePasswordConfirmed(int)));
        } else {
            //User defined
            Q_ASSERT(value == PacStorePasswordUserDefined);
            qDebug("CpEapPacStoreUi::pacStorePasswordChanged - User defined");
            // Read from PAC store config if PAC store exists
            EapQtPacStoreConfig pacStoreConfig;
            bool configurationRead = mConfigIf->readPacStoreConfiguration(
                pacStoreConfig);
            if (!configurationRead) {
                qDebug("CpEapPacStoreUi::pacStorePasswordChanged - read PAC store configuration failed.");
            }

            if (pacStoreConfig.value(EapQtPacStoreConfig::PacStoreState).toInt() 
                == EapQtPacStoreConfig::PacStoreStatePasswordRequired) {
                // PAC store exists, show 'PAC store password' query 
                qDebug("CpEapPacStoreUi::pacStorePasswordChanged - Exist password query");
                showExistPasswordQuery();
            } else if (pacStoreConfig.value(EapQtPacStoreConfig::PacStoreState).toInt()
                == EapQtPacStoreConfig::PacStoreStateStoreNotExists) {
                // PAC store doesn't exist, show create password query
                qDebug("CpEapPacStoreUi::pacStorePasswordChanged - Create new password");
                showNewPasswordQuery();
            } else {
                // If password already stored no prompt needed
                qDebug("CpEapPacStoreUi::pacStorePasswordChanged - Password stored");
            }
        }    
    }
}

/*!
 * Slot for handling "Reset PAC store" button presses.
 * 
 * @param [in] index  Obsolete parameter, not needed
 * @param [in] value  Obsolete parameter, not needed
 */
void CpEapPacStoreUi::resetPacStoreButtonPressed(
    QPersistentModelIndex index, 
    QVariant value)
{
    qDebug("CpEapPacStoreUi::resetPacStoreButtonPressed");

    Q_UNUSED(index);
    Q_UNUSED(value);

    //Show message box to confirm the PAC store resetting
    HbMessageBox *questionBox = new HbMessageBox(HbMessageBox::MessageTypeQuestion);
    questionBox->setObjectName("CpEapPacStoreUiRestPacStoreQuestion");
    questionBox->setText(hbTrId("txt_occ_info_remove_pac_store_all_credentials_wil"));
    questionBox->setModal(true);
    questionBox->setTimeout(HbPopup::NoTimeout);
    questionBox->setAttribute(Qt::WA_DeleteOnClose);
    questionBox->setStandardButtons(HbMessageBox::Yes | HbMessageBox::No);
    questionBox->open(this,SLOT(resetPacStoreConfirmed(int)));
}

/*!
 * Slot for clear PAC store Password after confirmed.
 * 
 * @param [in] action  User action
 */
void CpEapPacStoreUi::clearPacStorePasswordConfirmed(int action)
{
    qDebug("CpEapPacStoreUi::clearPacStorePasswordConfirmed()");
    if (action == HbMessageBox::Yes) {
        // User Clicked Yes
        // Clear PAC store password
        EapQtPacStoreConfig pacStoreConfig;
        pacStoreConfig.setValue(EapQtPacStoreConfig::PacStoreSavePassword, false);
        bool status = mConfigIf->savePacStoreConfiguration(
            pacStoreConfig);
        qDebug("CpEapPacStoreUi::clearPacStorePasswordConfirmed - status: %d", status);
        mPacStorePasswordState = PacStorePasswordPrompt;
        // Show error note to user
        if (!status) {
            // Show error note to user
            showMessageBox(
                HbMessageBox::MessageTypeWarning,
                hbTrId("txt_occ_info_unable_to_save_setting"));            
        }
    } else {
        // User Clicked No
        Q_ASSERT(action == HbMessageBox::No);
        // Set PAC store password back to 'User defined'
        setPacStorePasswordState(PacStorePasswordUserDefined);
    }
}

/*!
 * Slot for reset PAC store after confirmed.
 * 
 * @param [in] action  User action
 */
void CpEapPacStoreUi::resetPacStoreConfirmed(int action)
{
    qDebug("CpEapPacStoreUi::resetPacStoreConfirmed()");
    if (action == HbMessageBox::Yes) {
        // User Clicked Yes
        // Reset PAC Store
        EapQtPacStoreConfig pacStoreConfig;
        pacStoreConfig.setValue(EapQtPacStoreConfig::PacStoreReset, true);
        bool status = mConfigIf->savePacStoreConfiguration(
            pacStoreConfig);
        qDebug("CpEapPacStoreUi::resetPacStoreConfirmed - reset status: %d", status);
        if (!status) {
            // Show error note to user
            showMessageBox(
                HbMessageBox::MessageTypeWarning,
                hbTrId("txt_occ_info_unable_to_save_setting"));
        }
        
        // Set PAC store password selection to 'Prompt'
        setPacStorePasswordState(PacStorePasswordPrompt);
    } else {
        // User Clicked No
        Q_ASSERT(action == HbMessageBox::No);
        // Do nothing (don't reset PAC store)
        qDebug("CpEapPacStoreUi::resetPacStoreConfirmed - Do not reset.");
    }
}

/*!
 * Slot for confirm given PAC store password when PAC store exists
 */
void CpEapPacStoreUi::completeExistPasswordQuery()
{
    qDebug("CpEapPacStoreUi::completeExistPasswordQuery()");
    QString password = mExistPasswordDialog->value().toString();
    if (mValidatorPacStore->validate(password) == EapQtValidator::StatusOk) {
        qDebug("CpEapPacStoreUi::completeExistPasswordQuery() - save password");
        // Password is OK, save it
        EapQtPacStoreConfig pacStoreConfig;
        pacStoreConfig.setValue(EapQtPacStoreConfig::PacStorePassword, password);
        pacStoreConfig.setValue(EapQtPacStoreConfig::PacStoreSavePassword, true);
        bool status = mConfigIf->savePacStoreConfiguration(
            pacStoreConfig);
        qDebug("CpEapPacStoreUi::completeExistPasswordQuery - save status: %d", status);
        if (status) {
            mPacStorePasswordState = PacStorePasswordUserDefined;            
        } else {
            setPacStorePasswordState(PacStorePasswordPrompt);
            // Show error note to user
            showMessageBox(
                HbMessageBox::MessageTypeWarning,
                hbTrId("txt_occ_info_unable_to_save_setting"));
        }

    } else {
        // Existing password cannot be changed
        // Set PAC store password selection back to 'Prompt'
        setPacStorePasswordState(PacStorePasswordPrompt);
        // Show info popup
        HbMessageBox *infoBox = new HbMessageBox(HbMessageBox::MessageTypeInformation);
        infoBox->setObjectName("CpEapPacStoreUiPasswordCannotChangeInfo");
        infoBox->setText(hbTrId("txt_occ_info_existing_password_cannot_be_changed"));
        infoBox->setModal(true);
        infoBox->setTimeout(HbPopup::NoTimeout);
        infoBox->setAttribute(Qt::WA_DeleteOnClose);
        infoBox->setStandardButtons(HbMessageBox::Ok);
        infoBox->open();
    }
}

/*!
 * Slot for save given PAC store password when no PAC store exists
 */
void CpEapPacStoreUi::completeNewPasswordQuery()
{
    qDebug("CpEapPacStoreUi::completeNewPasswordQuery()");
    QString password = mNewPasswordDialog->value(0).toString();
    QString passwordConfirm = mNewPasswordDialog->value(1).toString();

    if (password == passwordConfirm &&
        mValidatorPacStore->validate(password) == EapQtValidator::StatusOk) {
        // Password is OK, save it
        qDebug("CpEapPacStoreUi::completeNewPasswordQuery() - password OK. Save it.");
        EapQtPacStoreConfig pacStoreConfig;
        pacStoreConfig.setValue(EapQtPacStoreConfig::PacStorePassword, password);
        pacStoreConfig.setValue(EapQtPacStoreConfig::PacStoreSavePassword, true);
        bool status = mConfigIf->savePacStoreConfiguration(
            pacStoreConfig);
        qDebug("CpEapPacStoreUi::completeNewPasswordQuery - save status: %d", status);
        if (status) {
            mPacStorePasswordState = PacStorePasswordUserDefined;
        } else {
            setPacStorePasswordState(PacStorePasswordPrompt);
            // Show error note to user
            showMessageBox(
                HbMessageBox::MessageTypeWarning,
                hbTrId("txt_occ_info_unable_to_save_setting"));
        }
    } else {
        // Password is not OK, show info popup
        qDebug("CpEapPacStoreUi::completeNewPasswordQuery() - password Not OK. Show popup.");
        HbMessageBox *infoBox = new HbMessageBox(HbMessageBox::MessageTypeInformation);
        infoBox->setObjectName("CpEapPacStoreUiInvalidPasswordInfo");
        if (password != passwordConfirm) {
            infoBox->setText(hbTrId("txt_occ_info_passwords_do_not_match_try_again"));
        } else {
            infoBox->setText(hbTrId("txt_occ_info_invalid_input"));
        }
        infoBox->setModal(true);
        infoBox->setTimeout(HbPopup::NoTimeout);
        infoBox->setAttribute(Qt::WA_DeleteOnClose);
        infoBox->setStandardButtons(HbMessageBox::Ok);
        infoBox->open(this,SLOT(invalidPasswordInfoClosed(int)));
    }
}

/*!
 * This function is called when user selects CANCEL from
 * PAC store password or New PAC store password query popup.
 * PAC store password selection is changed back to 'Prompt'.
 */
void CpEapPacStoreUi::cancelPasswordQuery()
{
    qDebug("CpEapPacStoreUi::cancelPasswordQuery()");
    // Set PAC store password selection back to 'Prompt'
    setPacStorePasswordState(PacStorePasswordPrompt);
}

/*!
 * This function is called when user selects OK from
 * 'Passwords do not match' or 'Invalid input' information popup.
 * New PAC store password query dialog is shown again
 * 
 * @param [in] action  Obsolete parameter, not needed
 */
void CpEapPacStoreUi::invalidPasswordInfoClosed(int action)
{
    qDebug("CpEapPacStoreUi::invalidPasswordInfoClosed() - Show query again.");
    Q_UNUSED(action);
    
    showNewPasswordQuery();    
}
