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
* Description: EAP-FAST PAC Store Password Query Dialog implementation
*
*/

/*
* %version: 12 %
*/

// System includes
#include <HbTranslator>
#include <HbAction>
#include <HbTranslator>
#include <HbMessageBox>
#include <HbParameterLengthLimiter>
#include <HbEditorInterface>
#include <EapSettings.h>

// User includes
#include "eapfastpacstorepwquerydialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapfastpacstorepwquerydialogTraces.h"
#endif


/*!
 * \class EapFastPacStorePwQueryDialog
 * \brief Implements EAP-FAST PAC Store Password Query Dialog. 
 */

// External function prototypes

// Local constants
static const uint PacStorePwQueryTimeout = 60000;
 
// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param [in]  parameters Parameters for the Constructor.
 */
EapFastPacStorePwQueryDialog::EapFastPacStorePwQueryDialog(const QVariantMap &parameters) 
 :mEdit(NULL), 
 mTranslator(new HbTranslator("eapprompts")),
 mErrMsgTranslator(new HbTranslator("cpdestinationplugin")),
 mClose(false)
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_EAPFASTPACSTOREPWQUERYDIALOG_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::EapFastPacStorePwQueryDialog ENTER");
    
    Q_UNUSED(parameters)

    createDialog();
     
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_EAPFASTPACSTOREPWQUERYDIALOG_EXIT );
    qDebug("EapFastPacStorePwQueryDialog::EapFastPacStorePwQueryDialog EXIT");
}
    
/*!
 * The construction of the dialog
 */ 
void EapFastPacStorePwQueryDialog::createDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::createDialog ENTER");

    QString labelText(hbTrId("txt_occ_dialog_pac_store_password"));
    
    // Set the dialog to be on the screen for 60 seconds, unless
    // the user reacts earlier
    this->setModal(true);
    this->setTimeout(PacStorePwQueryTimeout);
    this->setDismissPolicy(HbPopup::NoDismiss);
    this->setDismissOnAction(false);    
    this->setPromptText(labelText, 0);  
    
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
   
    OstTraceFunctionExit0( DUP1_EAPFASTPACSTOREPWQUERYDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastPacStorePwQueryDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapFastPacStorePwQueryDialog::~EapFastPacStorePwQueryDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_DEAPFASTPACSTOREPWQUERYDIALOG_ENTRY );
    
    // The dialog widgets are deleted as the dialog is deleted        
    
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_DEAPFASTPACSTOREPWQUERYDIALOG_EXIT );
}


/*!
 * Function is called when the Ok Action button is pressed
 */
void EapFastPacStorePwQueryDialog::okPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_OKPRESSED_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::okPressed ENTER");
    
    QVariantMap data;
        
    data["password"] = mEdit->text();
      
    qDebug("EapFastPacStorePwQueryDialog::okPressed: emit deviceDialogData");
    
    emit deviceDialogData(data); 
            
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_OKPRESSED_EXIT );
    qDebug("EapFastPacStorePwQueryDialog::okPressed EXIT");
}

/*!
 * Function is called when the Cancel Action button is pressed
 */
void EapFastPacStorePwQueryDialog::cancelPressed()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_CANCELPRESSED_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::cancelPressed ENTER");
    
    if (!mClose) {
        mClose = true;
        closeDeviceDialog(true);
    }   
    qDebug("EapFastPacStorePwQueryDialog::cancelPressed EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_CANCELPRESSED_EXIT );
}

/*!
 * Function is called when the dialog is about to close
 */
void EapFastPacStorePwQueryDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::closingDialog ENTER");
     
    qDebug("EapFastPacStorePwQueryDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 *
 * @param [in] parameters Parameters for the method
 * @return true always.
 */  
bool EapFastPacStorePwQueryDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::setDeviceDialogParameters ENTER");
        
    QString key("pwdcorrectind");
    
    bool isPwdCorrect = false;
    
    //Get the needed information from parameters that indicates 
    //the correctness of the password 
    if ( parameters.empty() == false ) {
        if ( parameters.contains(key) ) {
            QVariant variant = parameters.value(key);
            isPwdCorrect = variant.toBool();
            }
        }      
    
    if ( isPwdCorrect != false ) {
        qDebug("EapFastPacStorePwQueryDialog::setDeviceDialogParameters: isPwdCorrect == TRUE");    
        closeDeviceDialog(true);
        }
    else {
        HbMessageBox *box = 
            new HbMessageBox(hbTrId("txt_occ_info_incorrect_password_msg_box"),
            HbMessageBox::MessageTypeInformation);
        
        box->setAttribute(Qt::WA_DeleteOnClose);
        box->open();       
        }
   
    qDebug("EapFastPacStorePwQueryDialog::setDeviceDialogParameters EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapFastPacStorePwQueryDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapFastPacStorePwQueryDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastPacStorePwQueryDialog::closeDeviceDialog ENTER");
        
    //If the user closes the dialog, then the deviceDialogClosed is emitted
    if ( byClient == true )
        {
        qDebug("EapFastPacFilePwQueryDialog::closeDeviceDialog: emit deviceDialogClosed");
        emit deviceDialogClosed();
        }
    
    qDebug("EapFastPacStorePwQueryDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapFastPacStorePwQueryDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPACSTOREPWQUERYDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    OstTraceFunctionExit0( EAPFASTPACSTOREPWQUERYDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastPacStorePwQueryDialog*>(this);
}

