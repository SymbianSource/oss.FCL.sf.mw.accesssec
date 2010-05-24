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

#include "eapmschapv2pwdexpirednotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif

// The index numbers of the button of the dialog
const int okButtonIndex = 1;

/**
 * The constructor
 */
EapMschapv2PwdExpNoteDialog::EapMschapv2PwdExpNoteDialog(const QVariantMap &parameters)
:HbMessageBox("default text...",HbMessageBox::MessageTypeInformation),    
mActionOk(NULL),
mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_EAPMSCHAPV2PWDEXPNOTEDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::EapMschapv2PwdExpNoteDialog ENTER");

    createDialog( parameters );
    
    mOkActionPressed = false;
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_EAPMSCHAPV2PWDEXPNOTEDIALOG_EXIT );
    qDebug("EapMschapv2PwdExpNoteDialog::EapMschapv2PwdExpNoteDialog EXIT");
}

    
/**
 * The construction of the dialog
 */ 
void EapMschapv2PwdExpNoteDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::createDialog ENTER");
     
    QString text = QString(hbTrId("txt_occ_info_eapmschapv2_password_has_expired_yo"));
    
    Q_UNUSED(parameters)
        
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
                   
    this->setText(text);    
    this->setIconVisible(true);
        
    QList<QAction*> action_list = this->actions();
        
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        }
    
    mActionOk = new HbAction(hbTrId("txt_common_button_ok_single_dialog"),this); 
    this->addAction(mActionOk);
    
    disconnect(mActionOk, SIGNAL(triggered()),this, SLOT(close()));
    bool connected = connect(mActionOk, SIGNAL(triggered()), this, SLOT(okPressed()));
    Q_ASSERT(connected == true);
        
    // Connect the about to close and hide signals, so that we are able to inform 
    // the caller that the dialog was closed    
    connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPMSCHAPV2PWDEXPNOTEDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapMschapv2PwdExpNoteDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapMschapv2PwdExpNoteDialog::~EapMschapv2PwdExpNoteDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEAPMSCHAPV2PWDEXPNOTEDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEAPMSCHAPV2PWDEXPNOTEDIALOG_EXIT );
}

/**
 * Function is called when the Ok Action button is pressed
 */
void EapMschapv2PwdExpNoteDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_OKBUTTONPRESSED_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::okPressed ENTER");
    
    if ( mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
            QVariant variant(okButtonIndex);
            data.insert("okbutton", variant);
            // emit the data of the selected button and close the dialog
            qDebug("EapMschapv2PwdExpNoteDialog::okPressed: emit deviceDialogData");
            emit deviceDialogData(data);
    
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_OKBUTTONPRESSED_EXIT );
    qDebug("EapMschapv2PwdExpNoteDialog::okPressed EXIT");
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapMschapv2PwdExpNoteDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapMschapv2PwdExpNoteDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapMschapv2PwdExpNoteDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/**
 * Not supported, 0 always returned
 */
int EapMschapv2PwdExpNoteDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapMschapv2PwdExpNoteDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::closeDeviceDialog ENTER");
        
    if ( byClient == true ) {
        qDebug("EapMschapv2PwdExpNoteDialog::closeDeviceDialog: emit deviceDialogClosed");  
        emit deviceDialogClosed(); 
        }
    
    qDebug("EapMschapv2PwdExpNoteDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapMschapv2PwdExpNoteDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::deviceDialogWidget ENTER");
    
    qDebug("EapMschapv2PwdExpNoteDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapMschapv2PwdExpNoteDialog*>(this);
}

