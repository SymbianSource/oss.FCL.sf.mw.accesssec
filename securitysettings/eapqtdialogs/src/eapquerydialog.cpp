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
* Description: EAP Challenge query Dialog implementation
*
*/

/*
* %version: 5 %
*/

// System includes
#include <HbLabel>
#include <HbAction>
#include <HbTranslator>
#include <HbParameterLengthLimiter>

// User includes
#include "eapquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapquerydialogTraces.h"
#endif

/*!
 * \class EapQueryDialog
 * \brief Implements EAP Challenge query Dialog. 
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
EapQueryDialog::EapQueryDialog(const QVariantMap &parameters)
:mTranslator(new HbTranslator("eapprompts")),
mOkActionPressed(false)    
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_EAPQUERYDIALOG_ENTRY );
    qDebug("EapQueryDialog::EapQueryDialog ENTER");
        
    createDialog( parameters );
    
    OstTraceFunctionExit0( EAPQUERYDIALOG_EAPQUERYDIALOG_EXIT );
    qDebug("EapQueryDialog::EapQueryDialog EXIT");
}

/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapQueryDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapQueryDialog::createDialog ENTER");
     
    QString message;   
    QString authMethodstr; 
    QString keyauthmethod("authmethod");  
    QString keymessage("messagetxt");    
    QVariant tmpVariant;  
    
    //Get auth method and message string from parameters          
    if ( parameters.empty() == false ) {
      
        if ( parameters.contains(keyauthmethod) ) {
            tmpVariant = parameters.value(keyauthmethod);
            authMethodstr = tmpVariant.toString();
            }  
        if ( parameters.contains(keymessage) ) {
            tmpVariant = parameters.value(keymessage);
            message = tmpVariant.toString();
            }
        }    
    
    QString labelText1(HbParameterLengthLimiter(
        hbTrId("txt_occ_title_1_message").arg(authMethodstr)));
    QString labelText2 = message; 
    
    //Set the dialog to be on the screen until user reacts
    //by pressing the Action button
    this->setModal(true);
    this->setTimeout(HbPopup::NoTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
               
    HbLabel* label1 = new HbLabel;
    Q_ASSERT(label1 != NULL);
    label1->setPlainText(labelText1);
    label1->setFontSpec(HbFontSpec(HbFontSpec::Primary));
    label1->setTextWrapping(Hb::TextWrapAnywhere);
    
    this->setHeadingWidget(label1);       
    this->setText(labelText2);    
    this->setIconVisible(false);
    
    //Remove all default actions from the dialog     
    QList<QAction*> action_list = this->actions();
    for ( int i = 0; i < action_list.count(); i++ ) {
        this->removeAction(action_list.at(i));
        }
        
    //Add a new Ok button action 
    HbAction* actionOk = new HbAction(hbTrId("txt_common_button_ok"),this); 
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
   
    OstTraceFunctionExit0( DUP1_EAPQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapQueryDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapQueryDialog::~EapQueryDialog()
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_DEAPQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted
    
    OstTraceFunctionExit0( EAPQUERYDIALOG_DEAPQUERYDIALOG_EXIT );
}

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapQueryDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_OKPRESSED_ENTRY );
    qDebug("EapQueryDialog::okPressed ENTER");
    
    if ( mOkActionPressed == false ) {
        
            mOkActionPressed = true;
            
            QVariantMap data;
            data["okbutton"] = okButtonIndex;
            
            // emit the data of the selected button and close the dialog
            qDebug("EapQueryDialog::okPressed: emit deviceDialogData");
            emit deviceDialogData(data);
    
            closeDeviceDialog(true);
    }
    OstTraceFunctionExit0( EAPQUERYDIALOG_OKPRESSED_EXIT );
    qDebug("EapQueryDialog::okPressed EXIT");
}

/*!
 * Function is called when the dialog is about to close
 */
void EapQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapQueryDialog::closingDialog ENTER");
 
    qDebug("EapQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */  
bool EapQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapQueryDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true ) {
        emit deviceDialogClosed();
    }
    
    qDebug("EapQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapQueryDialog::deviceDialogWidget ENTER");
    
    qDebug("EapQueryDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapQueryDialog*>(this);
}

