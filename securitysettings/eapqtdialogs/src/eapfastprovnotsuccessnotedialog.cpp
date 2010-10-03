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
* Description: EAP-FAST Provisioning not successfull note Dialog implementation
*
*/

/*
* %version: 6 %
*/

// System includes
#include <HbAction>
#include <HbTranslator>

// User includes
#include "eapfastprovnotsuccessnotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapfastprovnotsuccessnotedialogTraces.h"
#endif

/*!
 * \class EapFastProvNotSuccessNoteDialog
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
EapFastProvNotSuccessNoteDialog::EapFastProvNotSuccessNoteDialog(const QVariantMap &parameters)
:HbMessageBox(HbMessageBox::MessageTypeWarning),    
mTranslator(new HbTranslator("eapprompts")),
mOkActionPressed(false)
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_EAPFASTPROVNOTSUCCESSNOTEDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::EapFastProvNotSuccessNoteDialog ENTER");
    
    Q_UNUSED(parameters)

    createDialog();
    
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_EAPFASTPROVNOTSUCCESSNOTEDIALOG_EXIT );
    qDebug("EapFastProvNotSuccessNoteDialog::EapFastProvNotSuccessNoteDialog EXIT");
}
    
/*!
 * The construction of the dialog
 */ 
void EapFastProvNotSuccessNoteDialog::createDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::createDialog ENTER");
     
    QString text(hbTrId("txt_occ_info_provisioning_not_successful_reactiv"));
         
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
        
    // Connect the about to close and hide signals, so that we are able to inform 
    // the caller that the dialog was closed    
    connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPFASTPROVNOTSUCCESSNOTEDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastProvNotSuccessNoteDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapFastProvNotSuccessNoteDialog::~EapFastProvNotSuccessNoteDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_DEAPFASTPROVNOTSUCCESSNOTEDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_DEAPFASTPROVNOTSUCCESSNOTEDIALOG_EXIT );
}

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapFastProvNotSuccessNoteDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_OKBUTTONPRESSED_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::okPressed ENTER");
    
    if ( mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
            data["okbutton"] = okButtonIndex;
            
            // emit the data of the selected button and close the dialog
            qDebug("EapFastProvNotSuccessNoteDialog::okPressed: emit deviceDialogData");
            emit deviceDialogData(data);
    
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_OKBUTTONPRESSED_EXIT );
    qDebug("EapFastProvNotSuccessNoteDialog::okPressed EXIT");
}

/*!
 * Function is called when the dialog is about to close
 * 
 */
void EapFastProvNotSuccessNoteDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::closingDialog ENTER");
     
    qDebug("EapFastProvNotSuccessNoteDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */  
bool EapFastProvNotSuccessNoteDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapFastProvNotSuccessNoteDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapFastProvNotSuccessNoteDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::closeDeviceDialog ENTER");
            
    if ( byClient == true ) {
        emit deviceDialogClosed(); 
        }
    
    qDebug("EapFastProvNotSuccessNoteDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapFastProvNotSuccessNoteDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapFastProvNotSuccessNoteDialog::deviceDialogWidget ENTER");
    
    qDebug("EapFastProvNotSuccessNoteDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPFASTPROVNOTSUCCESSNOTEDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastProvNotSuccessNoteDialog*>(this);
}

