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
* Description: Dialog implementation
*
*/

#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtconfiginterface.h>
#include <eapqtconfig.h>
#include "eapusernamepwddialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE

#endif

/**
 * The constructor
 */
EapUsernamePwdDialog::EapUsernamePwdDialog(const QVariantMap &parameters) 
 :mEdit1(NULL), 
 mEdit2(NULL), 
 mUnameValidator(NULL),
 mPwdValidator(NULL),
 mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_EAPUSERNAMEPWDDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::EapUsernamePwdDialog ENTER");
        
    createDialog(parameters);
    
    mClose = false;
    mOkActionPressed = false;
    
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_EAPUSERNAMEPWDDIALOG_EXIT );
    qDebug("EapUsernamePwdDialog::EapUsernamePwdDialog EXIT");
}
    
/**
 * The construction of the dialog
 */ 
void EapUsernamePwdDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::createDialog ENTER");
     
    QString keyauthmethod = QString("authmethod");    
    QString keyuname = QString("username");
    QString keyeaptype = QString("eaptype");
        
    QString unamestr = QString("");
    QString authMethodstr = QString("FOO");
       
    if ( parameters.empty() == false ) {
        if ( parameters.contains(keyuname) ) {
            QVariant variant = parameters.value(keyuname);
            unamestr = variant.toString();
            }
        if ( parameters.contains(keyauthmethod) ) {
            QVariant variant = parameters.value(keyauthmethod);
            authMethodstr = variant.toString();
            }    
        } 
    
    QString labelText1 = QString(hbTrId("txt_occ_dialog_1_user_name").arg(authMethodstr));
    QString labelText2 = QString(hbTrId("txt_occ_dialog_password"));
    
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);    
    this->setAdditionalRowVisible(true);
    
    this->setPromptText(labelText1, 0);   
    mEdit1 = this->lineEdit(0);
    mEdit1->setText(unamestr);
    
    this->setPromptText(labelText2, 1);   
    mEdit2 = this->lineEdit(1);        
            
    QByteArray ba;
    
    if ( parameters.contains(keyeaptype) ) {
        QVariant variant = parameters.value(keyeaptype);
        ba = variant.toByteArray();
        } 
    Q_ASSERT( ba.isEmpty() == false );
    
    EapQtExpandedEapType e_type(ba);
    EapQtConfigInterface eap_config_if;
    
    mUnameValidator = eap_config_if.validatorEap(e_type,
                EapQtConfig::Username);
    mUnameValidator->updateEditor(mEdit1);
        
    mPwdValidator = eap_config_if.validatorEap(e_type,
                EapQtConfig::Password);    
    mPwdValidator->updateEditor(mEdit2);
        
    QList<QAction*> action_list = this->actions();
        
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        } 
    
    HbAction* actionOk = new HbAction(hbTrId("txt_common_button_ok"),this); 
    this->addAction(actionOk);
    HbAction* actionCancel = new HbAction(hbTrId("txt_common_button_cancel"),this);
    this->addAction( actionCancel );    
     
    disconnect(actionOk, SIGNAL(triggered()),this, SLOT(close()));
    bool connected = connect(actionOk, SIGNAL(triggered()), this, SLOT(okPressed()));
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
   
    OstTraceFunctionExit0( DUP1_EAPUSERNAMEPWDDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapUsernamePwdDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapUsernamePwdDialog::~EapUsernamePwdDialog()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_DEAPUSERNAMEPWDDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::~EapUsernamePwdDialog");
    
    //The dialog widgets are deleted as the dialog is deleted
    delete mPwdValidator;
    delete mUnameValidator;
    
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_DEAPUSERNAMEPWDDIALOG_EXIT );
}

/**
 * Line edit validator
 */
bool EapUsernamePwdDialog::validate() const
{
    qDebug("EapUsernamePwdDialog::validate ENTER");
    
    bool valid = false;

    if ( mUnameValidator->validate(mEdit1->text())== EapQtValidator::StatusOk   && 
         mPwdValidator->validate(mEdit2->text()) == EapQtValidator::StatusOk ) {
    
        qDebug("EapUsernamePwdDialog::validate(): returns TRUE");
        valid = true;
    }

    qDebug("EapUsernamePwdDialog::validate EXIT");
    return valid;
}

/**
 * Function is called when the Ok Action button is pressed
 */
void EapUsernamePwdDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_OKPRESSED_ENTRY );
    qDebug("EapUsernamePwdDialog::okPressed ENTER");
    
    if ( validate() == true && mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
    
            QString editStr1 = mEdit1->text();
    
            QString editStr2 = mEdit2->text();
        
            QVariant variant1(editStr1);
    
            QVariant variant2(editStr2);
    
            data["username"] = variant1;
            data["password"] = variant2;
      
            qDebug("EapUsernamePwdDialog::okPressed: emit deviceDialogData");
    
            emit deviceDialogData(data); 
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_OKPRESSED_EXIT );
    qDebug("EapUsernamePwdDialog::okPressed EXIT");
}

/**
 * Function is called when the Cancel Action button is pressed
 */
void EapUsernamePwdDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapUsernamePwdDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapUsernamePwdDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_CANCELPRESSED_EXIT );
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapUsernamePwdDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapUsernamePwdDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapUsernamePwdDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/**
 * Not supported, 0 always returned
 */
int EapUsernamePwdDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapUsernamePwdDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapUsernamePwdDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapUsernamePwdDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapUsernamePwdDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapUsernamePwdDialog*>(this);
}

