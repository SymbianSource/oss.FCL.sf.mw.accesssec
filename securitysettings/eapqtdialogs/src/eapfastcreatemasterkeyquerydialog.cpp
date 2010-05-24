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
* Description: Prompt Dialog implementation
*
*/

#include <HbMessageBox>
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtconfiginterface.h>
#include <eapqtconfig.h>
#include "eapfastcreatemasterkeyquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif


/**
 * The constructor
 */
EapFastCreateMasterKeyQueryDialog::EapFastCreateMasterKeyQueryDialog(const QVariantMap &parameters) 
 :mEdit1(NULL), 
  mEdit2(NULL), 
  mPwdValidator(NULL),
  mActionOk(NULL),
  mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_EAPFASTCREATEMASTERKEYQUERYDIALOG_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::EapFastCreateMasterKeyQueryDialog ENTER");
       
    createDialog(parameters);
    
    mClose = false;
    mOkActionPressed = false;
    
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_EAPFASTCREATEMASTERKEYQUERYDIALOG_EXIT );
    qDebug("EapFastCreateMasterKeyQueryDialog::EapFastCreateMasterKeyQueryDialog EXIT");
}
    
/**
 * The construction of the dialog
 */ 
void EapFastCreateMasterKeyQueryDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::createDialog ENTER");
    
    Q_UNUSED(parameters)
    
    QString labelText1 = QString(hbTrId("txt_occ_dialog_create_password_for_encrypted_pac_s"));
    QString labelText2 = QString(hbTrId("txt_occ_dialog_verify_password"));
        
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);    
    this->setAdditionalRowVisible(true);
    
    this->setPromptText(labelText1, 0);   
    mEdit1 = this->lineEdit(0);
    mEdit1->setEchoMode(HbLineEdit::Password);
    
    this->setPromptText(labelText2, 1);   
    mEdit2 = this->lineEdit(1);        
    mEdit2->setEchoMode(HbLineEdit::Password);
    
    EapQtConfigInterface eap_config_if;
    
    mPwdValidator = eap_config_if.validatorEap(EapQtExpandedEapType::TypeEapFast,
                EapQtConfig::Password);  
    mPwdValidator->updateEditor(mEdit1);
    
    QList<QAction*> action_list = this->actions();
        
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        } 
    
    mActionOk = new HbAction(hbTrId("txt_common_button_ok"),this); 
    this->addAction(mActionOk);
    
    HbAction* actionCancel = new HbAction(hbTrId("txt_common_button_cancel"),this);
    this->addAction(actionCancel);    
     
    disconnect(mActionOk, SIGNAL(triggered()),this, SLOT(close()));
    bool connected = connect(mActionOk, SIGNAL(triggered()), this, SLOT(okPressed()));
    Q_ASSERT(connected == true);
    
    disconnect(actionCancel, SIGNAL(triggered()),this, SLOT(close()));
    connected = connect(actionCancel, SIGNAL(triggered()), this, SLOT(cancelPressed()));
    Q_ASSERT(connected == true);
    
    // Connect the about to close and hide signals, so that we are able to inform 
    // the caller that the dialog was closed   
    connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPFASTCREATEMASTERKEYQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastCreateMasterKeyQueryDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapFastCreateMasterKeyQueryDialog::~EapFastCreateMasterKeyQueryDialog()
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_DEAPFASTCREATEMASTERKEYQUERYDIALOG_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::~EapFastCreateMasterKeyQueryDialog");
    
    //The dialog widgets are deleted as the dialog is deleted
    delete mPwdValidator;
    
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_DEAPFASTCREATEMASTERKEYQUERYDIALOG_EXIT );
}

/**
 * Line edit validator
 */
bool EapFastCreateMasterKeyQueryDialog::validate() const
{
    qDebug("EapFastCreateMasterKeyQueryDialog::validate");
    
    bool valid = false;
    
    EapQtValidator::Status test_status = mPwdValidator->validate(mEdit1->text());
    
    if ( mPwdValidator->validate(mEdit1->text())== EapQtValidator::StatusOk &&
        mEdit1->text() == mEdit2->text()) {
        qDebug("EapFastCreateMasterKeyQueryDialog::validate: ret val: TRUE");
        valid = true;
    }
    return valid;
}

/**
 * Function is called when the Ok Action button is pressed
 */
void EapFastCreateMasterKeyQueryDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_FIRSTBUTTONPRESSED_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::okPressed ENTER");
    
    if ( validate() == true ) {
         
            QVariantMap data;
    
            QString editStr1 = mEdit1->text();
         
            QVariant variant1(editStr1);
   
            data["password"] = variant1;
      
            qDebug("EapFastCreateMasterKeyQueryDialog::okPressed: emit deviceDialogData");
    
            emit deviceDialogData(data); 
            closeDeviceDialog(true);
        }
    else {
        HbMessageBox *box = 
            new HbMessageBox(hbTrId("txt_occ_info_passwords_do_not_match_try_again"),
            HbMessageBox::MessageTypeInformation);
        box->setAttribute(Qt::WA_DeleteOnClose);
        box->open();       
        }
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_FIRSTBUTTONPRESSED_EXIT );
    qDebug("EapFastCreateMasterKeyQueryDialog::okPressed EXIT");
}

/**
 * Function is called when the Cancel Action button is pressed
 */
void EapFastCreateMasterKeyQueryDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapFastCreateMasterKeyQueryDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CANCELPRESSED_EXIT );
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapFastCreateMasterKeyQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapFastCreateMasterKeyQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapFastCreateMasterKeyQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/**
 * Not supported, 0 always returned
 */
int EapFastCreateMasterKeyQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapFastCreateMasterKeyQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastCreateMasterKeyQueryDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapFastCreateMasterKeyQueryDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapFastCreateMasterKeyQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapFastCreateMasterKeyQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTCREATEMASTERKEYQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPFASTCREATEMASTERKEYQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastCreateMasterKeyQueryDialog*>(this);
}
