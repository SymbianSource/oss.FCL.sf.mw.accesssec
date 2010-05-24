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
#include "eappasswordquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif


/**
 * The constructor
 */
EapPasswordQueryDialog::EapPasswordQueryDialog(const QVariantMap &parameters) 
 :mEdit(NULL), 
 mPwdValidator(NULL),
 mActionOk(NULL)
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_EAPPASSWORDQUERYDIALOG_ENTRY );
    qDebug("EapPasswordQueryDialog::EapPasswordQueryDialog ENTER");

    createDialog(parameters);
    
    mClose = false;
    mOkActionPressed = false;
    
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_EAPPASSWORDQUERYDIALOG_EXIT );
    qDebug("EapPasswordQueryDialog::EapPasswordQueryDialog EXIT");
}
    
/**
 * The construction of the dialog
 */ 
void EapPasswordQueryDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapPasswordQueryDialog::createDialog ENTER");
         
    QString keyeaptype = QString("eaptype"); 
    QString keyauthmethod = QString("authmethod");    
    QString authMethodstr = QString("FOO");
       
    if ( parameters.empty() == false ) {
        if ( parameters.contains(keyauthmethod) ) {
            QVariant variant = parameters.value(keyauthmethod);
            authMethodstr = variant.toString();
            }    
        } 
    QString labelText = QString(hbTrId("txt_occ_dialog_1_password").arg(authMethodstr));
    
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
    this->setPromptText(labelText, 0);   
    mEdit = this->lineEdit(0);
    mEdit->setEchoMode(HbLineEdit::Password);
    
    QByteArray ba;
    
    if ( parameters.contains(keyeaptype) ) {
        QVariant variant3 = parameters.value(keyeaptype);
        ba = variant3.toByteArray();
        } 
    Q_ASSERT( ba.isEmpty() == false );
    
    EapQtExpandedEapType e_type(ba);
    EapQtConfigInterface eap_config_if;
         
    mPwdValidator = eap_config_if.validatorEap(e_type,
                EapQtConfig::Password); 
    
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
   
    OstTraceFunctionExit0( DUP1_EAPPASSWORDQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapPasswordQueryDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapPasswordQueryDialog::~EapPasswordQueryDialog()
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_DEAPPASSWORDQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted        
    delete mPwdValidator;
    
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_DEAPPASSWORDQUERYDIALOG_EXIT );
}

/**
 * Line edit validator
 */
bool EapPasswordQueryDialog::validate() const
{
    qDebug("EapPasswordQueryDialog::validate ENTER");
    
    bool valid = false;

    if ( mPwdValidator->validate(mEdit->text())== EapQtValidator::StatusOk ) {
        
        qDebug("EapPasswordQueryDialog::validate(): returns TRUE");
        valid = true;
    }
    
    qDebug("EapPasswordQueryDialog::validate EXIT");
    return valid;
}


/**
 * Function is called when the Ok Action button is pressed
 */
void EapPasswordQueryDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_OKPRESSED_ENTRY );
    qDebug("EapPasswordQueryDialog::okPressed ENTER");
    
    if ( validate() == true && mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
    
            QString editStr = mEdit->text();
            
            QVariant variant(editStr);
    
            data["password"] = variant;
      
            qDebug("EapPasswordQueryDialog::okPressed: emit deviceDialogData");
    
            emit deviceDialogData(data); 
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_OKPRESSED_EXIT );
    qDebug("EapPasswordQueryDialog::okPressed EXIT");
}

/**
 * Function is called when the Cancel Action button is pressed
 */
void EapPasswordQueryDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapPasswordQueryDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapPasswordQueryDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_CANCELPRESSED_EXIT );
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapPasswordQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapPasswordQueryDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapPasswordQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapPasswordQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/**
 * Not supported, 0 always returned
 */
int EapPasswordQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapPasswordQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapPasswordQueryDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapUsernamePwdDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapPasswordQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapPasswordQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPPASSWORDQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPPASSWORDQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapPasswordQueryDialog*>(this);
}

