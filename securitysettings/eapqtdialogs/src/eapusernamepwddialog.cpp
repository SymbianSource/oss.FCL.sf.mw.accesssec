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
*   User authentication Dialog implementation
*
*/

/*
 * %version: 7 %
 */

// System includes
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtconfiginterface.h>
#include <eapqtconfig.h>
#include <HbParameterLengthLimiter>
#include <HbTranslator>
#include <HbLineEdit>
#include <HbAction>

// User includes
#include "eapusernamepwddialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapusernamepwddialogTraces.h"
#endif

/*!
 * \class EapUsernamePwdDialog
 * \brief Implements Username Password Input Dialog. 
 */

// External function prototypes

// Local constants
 
// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in]  parameters Parameters for the Constructor.
 */
EapUsernamePwdDialog::EapUsernamePwdDialog(const QVariantMap &parameters) 
 :mEdit1(NULL), 
 mEdit2(NULL), 
 mUnameValidator(NULL),
 mPwdValidator(NULL),
 mTranslator(new HbTranslator("eapprompts")),
 mClose(false),
 mOkActionPressed(false)
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_EAPUSERNAMEPWDDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::EapUsernamePwdDialog ENTER");
        
    createDialog(parameters);
        
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_EAPUSERNAMEPWDDIALOG_EXIT );
    qDebug("EapUsernamePwdDialog::EapUsernamePwdDialog EXIT");
}
    
/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapUsernamePwdDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::createDialog ENTER");
     
    QString keyauthmethod("authmethod");    
    QString keyuname("username");
    QString keyeaptype("eaptype");
        
    QString unamestr;
    QString authMethodstr;
    
    //Get default username (if exists) and 
    //auth method strings from parameters   
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
    
    QString labelText1(HbParameterLengthLimiter(hbTrId("txt_occ_dialog_1_user_name")).arg(authMethodstr));
    QString labelText2(HbParameterLengthLimiter(hbTrId("txt_occ_dialog_password")));
    
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);  
    this->setDismissOnAction(false);       
    this->setAdditionalRowVisible(true);
    
    //Set the first Line Edit (user name) to be on the screen
    this->setPromptText(labelText1, 0);   
    mEdit1 = this->lineEdit(0);
    //Set default user name string
    mEdit1->setText(unamestr);
    
    //Set the second Line Edit (password) to be on the screen also
    this->setPromptText(labelText2, 1);   
    mEdit2 = this->lineEdit(1);        
    
    //Get the EAP type for the Line Edits (Validator)
    QByteArray ba;
    if ( parameters.contains(keyeaptype) ) {
        QVariant variant = parameters.value(keyeaptype);
        ba = variant.toByteArray();
        } 
    Q_ASSERT( ba.isEmpty() == false );    
    EapQtExpandedEapType e_type(ba);
    EapQtConfigInterface eap_config_if;
    
    mUnameValidator.reset(eap_config_if.validatorEap(e_type,
                EapQtConfig::Username));
    Q_ASSERT( mUnameValidator.isNull() == false );
   
    mUnameValidator->updateEditor(mEdit1);
        
    mPwdValidator.reset(eap_config_if.validatorEap(e_type,
                EapQtConfig::Password));
    Q_ASSERT( mPwdValidator.isNull() == false );
        
    mPwdValidator->updateEditor(mEdit2);
    
    //Remove all default actions from the dialog 
    QList<QAction*> action_list = this->actions();    
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        } 
    
    //Add a new Ok button action 
    HbAction* actionOk = new HbAction(hbTrId("txt_common_button_ok"),this); 
    this->addAction(actionOk);
    //Add a new Cancel button action
    HbAction* actionCancel = new HbAction(hbTrId("txt_common_button_cancel"),this);
    this->addAction( actionCancel );    
    
    //Connect to a SLOT owned by this class 
    bool connected = connect(actionOk, SIGNAL(triggered()), this, SLOT(okPressed()));
    Q_ASSERT(connected == true);
    
    //Connect to a SLOT owned by this class 
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

/*!
 * Destructor
 */
EapUsernamePwdDialog::~EapUsernamePwdDialog()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_DEAPUSERNAMEPWDDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::~EapUsernamePwdDialog");
    
    //The dialog widgets are deleted as the dialog is deleted
    // mPwdValidator:   scoped pointer deleted automatically
    // mUnameValidator: scoped pointer deleted automatically
    
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_DEAPUSERNAMEPWDDIALOG_EXIT );
}

/*!
 * Line edit validator
 *
 * @return true if content is valid.
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

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapUsernamePwdDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_OKPRESSED_ENTRY );
    qDebug("EapUsernamePwdDialog::okPressed ENTER");
    
    if ( validate() == true && mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
     
            data["username"] = mEdit1->text();
            data["password"] = mEdit2->text();
      
            qDebug("EapUsernamePwdDialog::okPressed: emit deviceDialogData");
    
            emit deviceDialogData(data); 
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_OKPRESSED_EXIT );
    qDebug("EapUsernamePwdDialog::okPressed EXIT");
}

/*!
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

/*!
 * Function is called when the dialog is about to close
 */
void EapUsernamePwdDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapUsernamePwdDialog::closingDialog ENTER");
     
    qDebug("EapUsernamePwdDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
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

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapUsernamePwdDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
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

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapUsernamePwdDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPUSERNAMEPWDDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapUsernamePwdDialog*>(this);
}

