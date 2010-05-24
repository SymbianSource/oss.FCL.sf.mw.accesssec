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

#include "eapfastprovnotsuccessnotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif

// The index numbers of the button of the dialog
const int okButtonIndex = 1;

/**
 * The constructor
 */
EapFastProvNotSuccessNoteDialog::EapFastProvNotSuccessNoteDialog(const QVariantMap &parameters)
:HbMessageBox("default text...",HbMessageBox::MessageTypeWarning),    
mActionOk(NULL),
mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_EAPMSCHAPV2PWDEXPNOTEDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::EapFastProvNotSuccessNoteDialog ENTER");

    createDialog( parameters );
    
    mOkActionPressed = false;
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_EAPMSCHAPV2PWDEXPNOTEDIALOG_EXIT );
    qDebug("EapFastProvNotSuccessNoteDialog::EapFastProvNotSuccessNoteDialog EXIT");
}

    
/**
 * The construction of the dialog
 */ 
void EapFastProvNotSuccessNoteDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::createDialog ENTER");
     
    QString text = QString(hbTrId("txt_occ_info_provisioning_not_successful_reactiv"));
    
    Q_UNUSED(parameters)
        
    //Set the dialog to be on the screen until user reacts
    //by pressing the Action button
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
    qDebug("EapFastProvNotSuccessNoteDialog::createDialog EXIT");
}

/**
 * Destructor
 */
EapFastProvNotSuccessNoteDialog::~EapFastProvNotSuccessNoteDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEAPMSCHAPV2PWDEXPNOTEDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEAPMSCHAPV2PWDEXPNOTEDIALOG_EXIT );
}

/**
 * Function is called when the Ok Action button is pressed
 */
void EapFastProvNotSuccessNoteDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_OKBUTTONPRESSED_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::okPressed ENTER");
    
    if ( mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
            QVariant variant(okButtonIndex);
            data.insert("okbutton", variant);
            // emit the data of the selected button and close the dialog
            qDebug("EapFastProvNotSuccessNoteDialog::okPressed: emit deviceDialogData");
            emit deviceDialogData(data);
    
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_OKBUTTONPRESSED_EXIT );
    qDebug("EapFastProvNotSuccessNoteDialog::okPressed EXIT");
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapFastProvNotSuccessNoteDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapFastProvNotSuccessNoteDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
 */ 
bool EapFastProvNotSuccessNoteDialog::setDeviceDialogParameters
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
int EapFastProvNotSuccessNoteDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
 */
void EapFastProvNotSuccessNoteDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::closeDeviceDialog ENTER");
            
    if ( byClient == true ) {
        emit deviceDialogClosed(); 
        }
    
    qDebug("EapFastProvNotSuccessNoteDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapFastProvNotSuccessNoteDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::deviceDialogWidget ENTER");
    
    qDebug("EapFastProvNotSuccessNoteDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastProvNotSuccessNoteDialog*>(this);
}

