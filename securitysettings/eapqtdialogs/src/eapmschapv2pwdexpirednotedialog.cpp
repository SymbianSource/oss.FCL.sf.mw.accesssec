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
* Description: EAP-MSCHAPv2 password expired note Dialog implementation
*
*/

/*
* %version: 5 %
*/

// System includes
#include <HbAction>
#include <HbTranslator>

// User includes
#include "eapmschapv2pwdexpirednotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapmschapv2pwdexpirednotedialogTraces.h"
#endif

/*!
 * \class EapMschapv2NewPwdDialog
 * \brief Implements EAP-MSCHAPv2 New Password Input Dialog. 
 */

// External function prototypes

// Local constants

//! The index numbers of the button of the dialog
static const int okButtonIndex = 1;
 
// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in]  parameters Parameters for the Constructor.
 */
EapMschapv2PwdExpNoteDialog::EapMschapv2PwdExpNoteDialog(const QVariantMap &parameters)
:HbMessageBox("default text...",HbMessageBox::MessageTypeInformation),    
mTranslator(new HbTranslator("eapprompts")),
mOkActionPressed(false)
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_EAPMSCHAPV2PWDEXPNOTEDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::EapMschapv2PwdExpNoteDialog ENTER");
    
    Q_UNUSED(parameters)

    createDialog();
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_EAPMSCHAPV2PWDEXPNOTEDIALOG_EXIT );
    qDebug("EapMschapv2PwdExpNoteDialog::EapMschapv2PwdExpNoteDialog EXIT");
}
    
/*!
 * The construction of the dialog
 */ 
void EapMschapv2PwdExpNoteDialog::createDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::createDialog ENTER");
     
    QString text(hbTrId("txt_occ_info_eapmschapv2_password_has_expired_yo"));
        
    //Set the dialog to be on the screen until user reacts
    //by pressing the Action button
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
                   
    this->setText(text);    
    this->setIconVisible(true);
    
    //Remove all default actions from the dialog          
    QList<QAction*> action_list = this->actions();
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        }
    
    //Add a new Ok button action 
    HbAction* actionOk = new HbAction(hbTrId("txt_common_button_ok_single_dialog"),this); 
    this->addAction(actionOk);
    
    //Connect to a SLOT owned by this class  
    bool connected = connect(actionOk, SIGNAL(triggered()), this, SLOT(okPressed()));
    Q_ASSERT(connected == true);
        
    //Connect the about to close and hide signals, so that we are able to inform 
    //the caller that the dialog was closed    
    connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPMSCHAPV2PWDEXPNOTEDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapMschapv2PwdExpNoteDialog::createDialog EXIT");
}

/*!
 * Destructor
 */
EapMschapv2PwdExpNoteDialog::~EapMschapv2PwdExpNoteDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEAPMSCHAPV2PWDEXPNOTEDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEAPMSCHAPV2PWDEXPNOTEDIALOG_EXIT );
}

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapMschapv2PwdExpNoteDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_OKBUTTONPRESSED_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::okPressed ENTER");
    
    if ( mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
            data["okbutton"] = okButtonIndex;    
            
            // emit the data of the selected button and close the dialog
            qDebug("EapMschapv2PwdExpNoteDialog::okPressed: emit deviceDialogData");
            emit deviceDialogData(data);
    
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_OKBUTTONPRESSED_EXIT );
    qDebug("EapMschapv2PwdExpNoteDialog::okPressed EXIT");
}

/*!
 * Function is called when the dialog is about to close
 * 
 */
void EapMschapv2PwdExpNoteDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::closingDialog ENTER");
     
    qDebug("EapMschapv2PwdExpNoteDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
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

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapMschapv2PwdExpNoteDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
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

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapMschapv2PwdExpNoteDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapMschapv2PwdExpNoteDialog::deviceDialogWidget ENTER");
    
    qDebug("EapMschapv2PwdExpNoteDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPMSCHAPV2PWDEXPNOTEDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapMschapv2PwdExpNoteDialog*>(this);
}

