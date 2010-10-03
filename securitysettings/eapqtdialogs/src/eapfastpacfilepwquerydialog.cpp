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
* Description: EAP-FAST PAC File Password Query Dialog implementation
*
*/

/*
* %version: 8 %
*/

// System includes
#include <HbTranslator>
#include <HbAction>
#include <HbParameterLengthLimiter>
#include <HbEditorInterface>
#include <EapSettings.h>

// User includes
#include "eapfastpacfilepwquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapfastpacfilepwquerydialogTraces.h"
#endif


/*!
 * \class EapFastPacFilePwQueryDialog
 * \brief Implements EAP-FAST PAC File Password Query Dialog. 
 */

// External function prototypes

// Local constants
static const uint PacFilePwQueryTimeout = 60000;
 
// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in]  parameters Parameters for the Constructor.
 */
EapFastPacFilePwQueryDialog::EapFastPacFilePwQueryDialog(const QVariantMap &parameters) 
 :mEdit(NULL), 
 mTranslator(new HbTranslator("eapprompts")),
 mClose(false),
 mOkActionPressed(false)
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_EAPFASTPACFILEQUERYDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::EapFastPacFilePwQueryDialog ENTER");
        
    createDialog(parameters);
    
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_EAPFASTPACFILEQUERYDIALOG_EXIT );
    qDebug("EapFastPacFilePwQueryDialog::EapFastPacFilePwQueryDialog EXIT");
}
    
/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapFastPacFilePwQueryDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::createDialog ENTER");
    
    QString filename;      
    QString key("pacfilename");
    
    //Get the filename from parameters   
    if ( parameters.empty() == false ) {
        if ( parameters.contains(key) ) {
            QVariant variant = parameters.value(key);
            filename = variant.toString();
            }
        }  

    QString mainText(HbParameterLengthLimiter(
        hbTrId("txt_occ_dialog_pac_file_password_for_1").arg(filename)));
    
    //Set the dialog to be on the screen for 60 seconds, unless
    //the user reacts earlier
    this->setModal(true);
    this->setTimeout(PacFilePwQueryTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
    this->setPromptText(mainText, 0);   
    mEdit = this->lineEdit(0);
    mEdit->setEchoMode(HbLineEdit::Password);
    mEdit->setMaxLength(KGeneralStringMaxLength);
    mEdit->setInputMethodHints(
        Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase | Qt::ImhNoPredictiveText);
    
    HbEditorInterface editInterface(mEdit);
    editInterface.setSmileyTheme(HbSmileyTheme());    
              
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
   
    OstTraceFunctionExit0( DUP1_EAPFASTPACFILEQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastPacFilePwQueryDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapFastPacFilePwQueryDialog::~EapFastPacFilePwQueryDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_DEAPFASTPACFILEQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted        
    
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_DEAPFASTPACFILEQUERYDIALOG_EXIT );
}

/*!
 * Function is called when the Ok Action button is pressed
 */
void EapFastPacFilePwQueryDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_FIRSTBUTTONPRESSED_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::okPressed ENTER");
    
    if ( mOkActionPressed == false ) {
        
        mOkActionPressed = true;
            
        QVariantMap data;
            
        data["password"] = mEdit->text();
      
        qDebug("EapFastPacFilePwQueryDialog::okPressed: emit deviceDialogData");
    
        emit deviceDialogData(data); 
        closeDeviceDialog(true);
        }
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_FIRSTBUTTONPRESSED_EXIT );
    qDebug("EapFastPacFilePwQueryDialog::okPressed EXIT");
}

/*!
 * Function is called when the Cancel Action button is pressed
 */
void EapFastPacFilePwQueryDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapFastPacFilePwQueryDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_CANCELPRESSED_EXIT );
}

/*!
 * Function is called when the dialog is about to close
 */
void EapFastPacFilePwQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::closingDialog ENTER");
     
    qDebug("EapFastPacFilePwQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */
bool EapFastPacFilePwQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapFastPacFilePwQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapFastPacFilePwQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapFastPacFilePwQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACFILEQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastPacFilePwQueryDialog*>(this);
}

