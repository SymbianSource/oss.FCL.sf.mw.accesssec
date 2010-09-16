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
* Description: EAP-FAST Install PAC Query Dialog implementation
*
*/

/*
* %version: 6 %
*/

// System includes
#include <HbTranslator>
#include <HbAction>
#include <HbParameterLengthLimiter>

// User includes
#include "eapfastinstallpacquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapfastinstallpacquerydialogTraces.h"
#endif

/*!
 * \class EapFastInstallPacQueryDialog
 * \brief Implements EAP-FAST Install PAC Query Dialog. 
 */

// External function prototypes

// Local constants

//! The index numbers of the button of the dialog
static const int yesButtonIndex = 1;
 
// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in]  parameters Parameters for the Constructor.
 */
EapFastInstallPacQueryDialog::EapFastInstallPacQueryDialog(const QVariantMap &parameters)
:HbMessageBox(HbMessageBox::MessageTypeQuestion),
mTranslator(new HbTranslator("eapprompts")),
mClose(false),
mYesActionPressed(false)
{
    OstTraceFunctionEntry0( EAPGTCQUERYDIALOG_EAPGTCQUERYDIALOG_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::EapFastInstallPacQueryDialog ENTER");
        
    createDialog( parameters );
        
    OstTraceFunctionExit0( EAPGTCQUERYDIALOG_EAPGTCQUERYDIALOG_EXIT );
    qDebug("EapFastInstallPacQueryDialog::EapFastInstallPacQueryDialog EXIT");
}
    
/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapFastInstallPacQueryDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPGTCQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::createDialog ENTER");
         
    QString servername;
    QString key("pacservername");
    
    //Get the server name from parameters   
    if ( parameters.empty() == false ) {
        if ( parameters.contains(key) ) {
            QVariant variant = parameters.value(key);
            servername = variant.toString();
            }
        }  
    
    QString mainText(HbParameterLengthLimiter(
        hbTrId("txt_occ_info_install_pac_from_server_1").arg(servername)));
    
    //Set the dialog to be on the screen until user reacts
    //by pressing any of the Action buttons
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
               
    this->setText(mainText);    
    this->setIconVisible(true);
    
    //Remove all default actions from the dialog          
    QList<QAction*> action_list = this->actions();       
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        }
    
    //Add a new Yes button action 
    HbAction* actionYes = new HbAction(hbTrId("txt_common_button_yes"),this); 
    this->addAction(actionYes);
    
    //Add a new No button action 
    HbAction* actionNo = new HbAction(hbTrId("txt_common_button_no"),this);
    this->addAction(actionNo);    
    
    //Connect to a SLOT owned by this class
    bool connected = connect(actionYes, SIGNAL(triggered()), this, SLOT(yesPressed()));
    Q_ASSERT(connected == true);
    
    //Connect to a SLOT owned by this class  
    connected = connect(actionNo, SIGNAL(triggered()), this, SLOT(noPressed()));
    Q_ASSERT(connected == true);
        
    // Connect the about to close and hide signals, so that we are able to inform 
    // the caller that the dialog was closed    
    connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPGTCQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastInstallPacQueryDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapFastInstallPacQueryDialog::~EapFastInstallPacQueryDialog()
{
    OstTraceFunctionEntry0( EAPGTCQUERYDIALOG_DEAPGTCQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    
    OstTraceFunctionExit0( EAPGTCQUERYDIALOG_DEAPGTCQUERYDIALOG_EXIT );
}

/*!
 * Function is called when the Yes Action button is pressed
 */
void EapFastInstallPacQueryDialog::yesPressed()
{
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_YESBUTTONPRESSED_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::yesPressed ENTER");
    
    if ( mYesActionPressed == false ) {
        
         mYesActionPressed = true;
            
         QVariantMap data;
         data["yesbutton"] = yesButtonIndex;
         
         // emit the data of the selected button and close the dialog
         qDebug("EapFastInstallPacQueryDialog::yesPressed: emit deviceDialogData");
         emit deviceDialogData(data);   
         closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_YESBUTTONPRESSED_EXIT );
    qDebug("EapFastInstallPacQueryDialog::yesPressed EXIT");
}

/*!
 * Function is called when the No Action button is pressed
 */
void EapFastInstallPacQueryDialog::noPressed()
{
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_NOPRESSED_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::noPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapFastInstallPacQueryDialog::noPressed EXIT");
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_NOPRESSED_EXIT );
}

/*!
 * Function is called when the dialog is about to close
 */
void EapFastInstallPacQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::closingDialog ENTER");
  
    qDebug("EapFastInstallPacQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */  
bool EapFastInstallPacQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapFastInstallPacQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapFastInstallPacQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::closeDeviceDialog ENTER");
            
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapFastInstallPacQueryDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapFastInstallPacQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapFastInstallPacQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTINSTALLPACQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapFastInstallPacQueryDialog::deviceDialogWidget ENTER");
    
    qDebug("EapFastInstallPacQueryDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPFASTINSTALLPACQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastInstallPacQueryDialog*>(this);
}

