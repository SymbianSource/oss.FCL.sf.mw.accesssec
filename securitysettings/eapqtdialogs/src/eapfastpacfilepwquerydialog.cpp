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
#include "eapfastpacfilepwquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif


/**
 * The constructor
 */
EapFastPacFilePwQueryDialog::EapFastPacFilePwQueryDialog(const QVariantMap &parameters) 
 :mEdit(NULL), 
 mPwdValidator(NULL),
 mActionOk(NULL),
 mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_EAPFASTPACFILEQUERYDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::EapFastPacFilePwQueryDialog ENTER");
        
    createDialog(parameters);
    
    mClose = false;
    
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_EAPFASTPACFILEQUERYDIALOG_EXIT );
    qDebug("EapFastPacFilePwQueryDialog::EapFastPacFilePwQueryDialog EXIT");
}
    
/**
 * The construction of the dialog
 */ 
void EapFastPacFilePwQueryDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::createDialog ENTER");
    
    QString filename = QString("foobar"); //default        
    QString key = QString("pacfilename");
       
    if ( parameters.empty() == false ) {
        if ( parameters.contains(key) ) {
            QVariant variant = parameters.value(key);
            filename = variant.toString();
            }
        }  

    QString mainText = 
        QString(hbTrId("txt_occ_dialog_pac_file_password_for_1").arg(filename));
    
    // Set the dialog to be on the screen for 60 seconds, unless
    // the user reacts earlier
    this->setModal(true);
    this->setTimeout(60000);
    this->setDismissPolicy(HbPopup::NoDismiss);
    this->setPromptText(mainText, 0);   
    mEdit = this->lineEdit(0);
    mEdit->setEchoMode(HbLineEdit::Password);
      
    EapQtConfigInterface eap_config_if;
        
    mPwdValidator = eap_config_if.validatorEap(EapQtExpandedEapType::TypeEapFast, 
                EapQtConfig::PacStorePasswordConfirmation);    
    mPwdValidator->updateEditor(mEdit);
        
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
   
    OstTraceFunctionExit0( DUP1_EAPFASTPACFILEQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastPacFilePwQueryDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapFastPacFilePwQueryDialog::~EapFastPacFilePwQueryDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_DEAPFASTPACFILEQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted        
    delete mPwdValidator;
    
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_DEAPFASTPACFILEQUERYDIALOG_EXIT );
}

/**
 * Line edit validator
 */
bool EapFastPacFilePwQueryDialog::validate() const
{
    qDebug("EapFastPacFilePwQueryDialog::validate");
    
    bool valid = false;

    if ( mPwdValidator->validate(mEdit->text())== EapQtValidator::StatusOk ) {
        qDebug("EapFastPacFilePwQueryDialog::validate: returns TRUE");
        valid = true;
    }
    return valid;
}

/**
 * Function is called when the Ok Action button is pressed
 */
void EapFastPacFilePwQueryDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_FIRSTBUTTONPRESSED_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::okPressed ENTER");
    
    if ( validate() == true ) {
            
        QVariantMap data;
    
        QString editStr = mEdit->text();
            
        QVariant variant(editStr);    
        
        data["password"] = variant;
      
        qDebug("EapFastPacFilePwQueryDialog::okPressed: emit deviceDialogData");
    
        emit deviceDialogData(data); 
        closeDeviceDialog(true);
        }
    else {
        HbMessageBox *box = 
            new HbMessageBox(
            hbTrId("txt_occ_info_incorrect_password_msg_box"),
            HbMessageBox::MessageTypeInformation);
        
        box->setAttribute(Qt::WA_DeleteOnClose);
        box->open();       
        }
        
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_FIRSTBUTTONPRESSED_EXIT );
    qDebug("EapFastPacFilePwQueryDialog::okPressed EXIT");
}

/**
 * Function is called when the Cancel Action button is pressed
 */
void EapFastPacFilePwQueryDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapFastPacFilePwQueryDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_CANCELPRESSED_EXIT );
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapFastPacFilePwQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapFastPacFilePwQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapFastPacFilePwQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/**
 * Not supported, 0 always returned
 */
int EapFastPacFilePwQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapFastPacFilePwQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapFastPacFilePwQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastPacFilePwQueryDialog*>(this);
}

