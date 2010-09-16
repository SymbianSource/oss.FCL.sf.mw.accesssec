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
*   EAP-MSCHAPv2 Old Password Input Dialog implementation
*
*/

/*
* %version: 7 %
*/

// System includes
#include <HbAction>
#include <HbTranslator>
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtconfiginterface.h>
#include <eapqtconfig.h>

// User includes
#include "eapmschapv2oldpwddialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapmschapv2oldpwddialogTraces.h"
#endif

/*!
 * \class EapMschapv2OldPwdDialog
 * \brief Implements EAP-MSCHAPv2 Old Password Input Dialog. 
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
EapMschapv2OldPwdDialog::EapMschapv2OldPwdDialog(const QVariantMap &parameters) 
 :mEdit(NULL), 
 mPwdValidator(NULL),
 mTranslator(new HbTranslator("eapprompts")),
 mOkActionPressed(false),
 mClose(false)
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_EAPMSCHAPV2OLDPWDDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::EapMschapv2OldPwdDialog ENTER");
        
    createDialog(parameters);
    
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_EAPMSCHAPV2OLDPWDDIALOG_EXIT );
    qDebug("EapMschapv2OldPwdDialog::EapMschapv2OldPwdDialog EXIT");
}
    
/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapMschapv2OldPwdDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::createDialog ENTER");

    QString labelText1(hbTrId("txt_occ_dialog_old_eapmschapv2_password"));
    
    Q_UNUSED(parameters)
    
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss); 
    this->setDismissOnAction(false);       
    this->setPromptText(labelText1, 0);      
    mEdit = this->lineEdit(0);
    mEdit->setEchoMode(HbLineEdit::Password);
      
    EapQtConfigInterface eap_config_if;
    
    mPwdValidator.reset(eap_config_if.validatorEap(EapQtExpandedEapType::TypeEapMschapv2, 
               EapQtConfig::Password )); 
    Q_ASSERT( mPwdValidator.isNull() == false );
         
    mPwdValidator->updateEditor(mEdit);
    
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
    this->addAction(actionCancel);    
    
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
   
    OstTraceFunctionExit0( DUP1_EAPMSCHAPV2OLDPWDDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapMschapv2OldPwdDialog::createDialog EXIT");
}

/*!
 * Destructor
 */
EapMschapv2OldPwdDialog::~EapMschapv2OldPwdDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_DEAPMSCHAPV2OLDPWDDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    // mPwdValidator:   scoped pointer deleted automatically
    
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_DEAPMSCHAPV2OLDPWDDIALOG_EXIT );
}

/*!
 * Line edit validator
 *
 * @return true if content is valid.
 */
bool EapMschapv2OldPwdDialog::validate() const
{
    qDebug("EapMschapv2OldPwdDialog::validate ENTER");
    
    bool valid = false;

    if ( mPwdValidator->validate(mEdit->text())== EapQtValidator::StatusOk ) {
        qDebug("EapMschapv2OldPwdDialog::validate: returns TRUE");
        valid = true;
    }
    
    qDebug("EapMschapv2OldPwdDialog::validate EXIT");
    return valid;
}

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapMschapv2OldPwdDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_OKPRESSED_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::okPressed ENTER");
    
    if ( validate() == true  && mOkActionPressed == false ) {
        
        mOkActionPressed = true;
            
        QVariantMap data;
    
        data["password"] = mEdit->text();
      
        qDebug("EapMschapv2OldPwdDialog::okPressed: emit deviceDialogData");
    
        emit deviceDialogData(data); 
        closeDeviceDialog(true);
        }

    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_OKPRESSED_EXIT );
    qDebug("EapMschapv2OldPwdDialog::okPressed EXIT");
}

/*!
 * Function is called when the Cancel Action button is pressed
 */
void EapMschapv2OldPwdDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapMschapv2OldPwdDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_CANCELPRESSED_EXIT );
}

/*!
 * Function is called when the dialog is about to close
 */
void EapMschapv2OldPwdDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::closingDialog ENTER");
 
    
    qDebug("EapMschapv2OldPwdDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */ 
bool EapMschapv2OldPwdDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapMschapv2OldPwdDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapMschapv2OldPwdDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapMschapv2OldPwdDialog::closeDeviceDialog ENTER");
            
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true ) {  
        qDebug("EapMschapv2OldPwdDialog::closeDeviceDialog: emit deviceDialogClosed");  
        emit deviceDialogClosed(); 
        }
    
    qDebug("EapMschapv2OldPwdDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapMschapv2OldPwdDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2OLDPWDDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2OLDPWDDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapMschapv2OldPwdDialog*>(this);
}

