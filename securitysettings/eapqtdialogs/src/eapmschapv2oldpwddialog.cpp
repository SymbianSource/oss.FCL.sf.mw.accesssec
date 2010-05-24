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

#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtconfiginterface.h>
#include <eapqtconfig.h>
#include "eapmschapv2oldpwddialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif


/**
 * The constructor
 */
EapMschapv2OldPwdDialog::EapMschapv2OldPwdDialog(const QVariantMap &parameters) 
 :mEdit(NULL), 
 mPwdValidator(NULL),
 mActionOk(NULL),
 mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_EAPFASTPACSTOREQUERYDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::EapMschapv2OldPwdDialog ENTER");
        
    createDialog(parameters);
    
    mClose = false;
    
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_EAPFASTPACSTOREQUERYDIALOG_EXIT );
    qDebug("EapMschapv2OldPwdDialog::EapMschapv2OldPwdDialog EXIT");
}
    
/**
 * The construction of the dialog
 */ 
void EapMschapv2OldPwdDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::createDialog ENTER");

    QString labelText1 = QString(hbTrId("txt_occ_dialog_old_eapmschapv2_password"));
    
    Q_UNUSED(parameters)
    
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);    
    this->setPromptText(labelText1, 0);      
    mEdit = this->lineEdit(0);
    mEdit->setEchoMode(HbLineEdit::Password);
      
    EapQtConfigInterface eap_config_if;
    
    mPwdValidator = eap_config_if.validatorEap(EapQtExpandedEapType::TypeEapMschapv2, 
               EapQtConfig::Password );      
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
   
    OstTraceFunctionExit0( DUP1_EAPFASTPACSTOREQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapMschapv2OldPwdDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapMschapv2OldPwdDialog::~EapMschapv2OldPwdDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_DEAPFASTPACSTOREQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    delete mPwdValidator;
    
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_DEAPFASTPACSTOREQUERYDIALOG_EXIT );
}

/**
 * Line edit validator
 */
bool EapMschapv2OldPwdDialog::validate() const
{
    qDebug("EapMschapv2OldPwdDialog::validate");
    
    bool valid = false;

    if ( mPwdValidator->validate(mEdit->text())== EapQtValidator::StatusOk ) {
        qDebug("EapMschapv2OldPwdDialog::validate: returns TRUE");
        valid = true;
    }
    return valid;
}

/**
 * Function is called when the Ok Action button is pressed
 */
void EapMschapv2OldPwdDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_FIRSTBUTTONPRESSED_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::okPressed ENTER");
    
    if ( validate() == true ) {
            
        QVariantMap data;
    
        QString editStr = mEdit->text();
            
        QVariant variant(editStr);
    
        data["password"] = variant;
      
        qDebug("EapMschapv2OldPwdDialog::okPressed: emit deviceDialogData");
    
        emit deviceDialogData(data); 
        closeDeviceDialog(true);
        }

    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_FIRSTBUTTONPRESSED_EXIT );
    qDebug("EapMschapv2OldPwdDialog::okPressed EXIT");
}

/**
 * Function is called when the Cancel Action button is pressed
 */
void EapMschapv2OldPwdDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapMschapv2OldPwdDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_CANCELPRESSED_EXIT );
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapMschapv2OldPwdDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapMschapv2OldPwdDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapMschapv2OldPwdDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/**
 * Not supported, 0 always returned
 */
int EapMschapv2OldPwdDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapMschapv2OldPwdDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::closeDeviceDialog ENTER");
            
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true ) {  
        qDebug("EapMschapv2OldPwdDialog::closeDeviceDialog: emit deviceDialogClosed");  
        emit deviceDialogClosed(); 
        }
    
    qDebug("EapMschapv2OldPwdDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapMschapv2OldPwdDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACSTOREQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapMschapv2OldPwdDialog*>(this);
}

