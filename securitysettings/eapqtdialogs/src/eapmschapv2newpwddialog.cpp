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
*   EAP-MSCHAPv2 New Password Input Dialog implementation
*
*/

/*
* %version: 7 %
*/

// System includes
#include <HbAction>
#include <HbLineEdit>
#include <HbTranslator>
#include <HbMessageBox>
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtconfiginterface.h>
#include <eapqtconfig.h>

// User includes
#include "eapmschapv2newpwddialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapmschapv2newpwddialogTraces.h"
#endif

/*!
 * \class EapMschapv2NewPwdDialog
 * \brief Implements EAP-MSCHAPv2 New Password Input Dialog. 
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
EapMschapv2NewPwdDialog::EapMschapv2NewPwdDialog(const QVariantMap &parameters) 
 :mEdit1(NULL), 
 mEdit2(NULL), 
 mPwdValidator(NULL),
 mTranslator(new HbTranslator("eapprompts")),
 mErrMsgTranslator(new HbTranslator("cpdestinationplugin")),
 mClose(false) 
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_EAPMSCHAPV2NEWPWDDIALOG_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::EapMschapv2NewPwdDialog ENTER");

    createDialog(parameters);
    
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_EAPMSCHAPV2NEWPWDDIALOG_EXIT );
    qDebug("EapMschapv2NewPwdDialog::EapMschapv2NewPwdDialog EXIT");
}
    
/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapMschapv2NewPwdDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::createDialog ENTER");
    
    Q_UNUSED(parameters)
    
    QString labelText1(hbTrId("txt_occ_dialog_new_eapmschapv2_password"));
    QString labelText2(hbTrId("txt_occ_dialog_verify_password"));
        
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
    this->setDismissOnAction(false);        
    this->setAdditionalRowVisible(true);
    
    //Set the first Line Edit to be on the screen
    this->setPromptText(labelText1, 0);   
    mEdit1 = this->lineEdit(0);
    mEdit1->setEchoMode(HbLineEdit::Password);
    
    //Set the second Line Edit to be on the screen also
    this->setPromptText(labelText2, 1);   
    mEdit2 = this->lineEdit(1);        
    mEdit2->setEchoMode(HbLineEdit::Password);
    
    EapQtConfigInterface eapConfigIf;
    
    mPwdValidator.reset( eapConfigIf.validatorEap(EapQtExpandedEapType::TypeEapMschapv2,
                EapQtConfig::Password ) );  
    Q_ASSERT( mPwdValidator.isNull() == false );                
                   
    mPwdValidator->updateEditor(mEdit1);
    
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
    
    //Connect the about to close and hide signals, so that we are able to inform 
    //the caller that the dialog was closed   
    connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPMSCHAPV2NEWPWDDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapMschapv2NewPwdDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapMschapv2NewPwdDialog::~EapMschapv2NewPwdDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_DEAPMSCHAPV2NEWPWDDIALOG_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::~EapMschapv2NewPwdDialog");
    
    //The dialog widgets are deleted as the dialog is deleted
    //mPwdValidator:   scoped pointer deleted automatically
    
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_DEAPMSCHAPV2NEWPWDDIALOG_EXIT );
}

/*!
 * Line edit validator
 *
 * @return true if content is valid.
 */
bool EapMschapv2NewPwdDialog::validate() const
{
    qDebug("EapMschapv2NewPwdDialog::validate ENTER");
    
    bool valid = false;
     
    if ( mPwdValidator->validate(mEdit1->text())== EapQtValidator::StatusOk &&
        mEdit1->text() == mEdit2->text()) {
        qDebug("EapMschapv2NewPwdDialog::validate: ret val: TRUE");
        valid = true;
    }
    qDebug("EapPasswordQueryDialog::validate EXIT");
    return valid;
}

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapMschapv2NewPwdDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_OKPRESSED_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::okPressed ENTER");
    
    if ( validate() == true ) {
         
        QVariantMap data;
    
        data["password"] = mEdit1->text();
      
        qDebug("EapMschapv2NewPwdDialog::okPressed: emit deviceDialogData");
    
        emit deviceDialogData(data); 
        closeDeviceDialog(true);
        }
    else {    
        HbMessageBox* box = new HbMessageBox(hbTrId("txt_occ_info_passwords_do_not_match_try_again"),
            HbMessageBox::MessageTypeInformation);
        
        box->setAttribute(Qt::WA_DeleteOnClose);
        box->open();       
        }
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_OKPRESSED_EXIT );
    qDebug("EapMschapv2NewPwdDialog::okPressed EXIT");
}

/*!
 * Function is called when the Cancel Action button is pressed
 */
void EapMschapv2NewPwdDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapMschapv2NewPwdDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_CANCELPRESSED_EXIT );
}

/*!
 * Function is called when the dialog is about to close
 */
void EapMschapv2NewPwdDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::closingDialog ENTER");
 
    qDebug("EapMschapv2NewPwdDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */  
bool EapMschapv2NewPwdDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapMschapv2NewPwdDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapMschapv2NewPwdDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapMschapv2NewPwdDialog::closeDeviceDialog ENTER");
            
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if( byClient == true ) {
        qDebug("EapMschapv2NewPwdDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapMschapv2NewPwdDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapMschapv2NewPwdDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2NEWPWDDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2NEWPWDDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapMschapv2NewPwdDialog*>(this);
}

