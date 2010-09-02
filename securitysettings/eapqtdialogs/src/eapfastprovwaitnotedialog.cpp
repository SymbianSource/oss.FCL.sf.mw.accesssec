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
* Description: Fast Provisioning Wait Notification Dialog implementation
*
*/

/*
* %version: 4 %
*/

// System includes
#include <HbTranslator>

// User includes
#include "eapfastprovwaitnotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapfastprovwaitnotedialogTraces.h"
#endif

/*!
 * \class EapFastProvWaitNoteDialog
 * \brief Implements Fast Provisioning Wait Notification Dialog. 
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
EapFastProvWaitNoteDialog::EapFastProvWaitNoteDialog(const QVariantMap &parameters)
:mTranslator(new HbTranslator("eapprompts"))
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_EAPFASTPROVWAITNOTEDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::EapFastProvWaitNoteDialog ENTER");

    createDialog( parameters );
        
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_EAPFASTPROVWAITNOTEDIALOG_EXIT );
    qDebug("EapFastProvWaitNoteDialog::EapFastProvWaitNoteDialog EXIT");
}
   
/*!
 * The construction of the dialog
 *
 * @param [in] parameters Parameters for the Construction of the dialog.
 */ 
void EapFastProvWaitNoteDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::createDialog ENTER");
    
    QString mainText;    
    QString key("notificationtxt");
    
    bool authProvWaitNote = false;
    
    //Get the needed information from parameters that indicates to type of the dialog
    //which is either a authenticated or a unauthenticated 
    if ( parameters.empty() == false ) {
        if ( parameters.contains(key) ) {
            QVariant variant = parameters.value(key);
            authProvWaitNote = variant.toBool();
            }
        }      
    
    if ( authProvWaitNote ) {
        mainText = QString(hbTrId("txt_occ_dpopinfo_authenticated_provisioning_in_pro"));       
    } else {
        mainText = QString(hbTrId("txt_occ_dpopinfo_unauthenticated_provisioning_in_p"));
    }
       
    // Set the dialog to be on the screen for 4 seconds.
    this->setTimeout(4000);
    this->setTitle(mainText);  
   
    // Connect the about to close and hide signals, so that we are able to inform 
    // the caller that the dialog was closed        
    bool connected = connect(this, SIGNAL(aboutToClose()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
    connected = connect(this, SIGNAL(aboutToHide()), this, SLOT(closingDialog()));
    Q_ASSERT(connected == true);
   
    OstTraceFunctionExit0( DUP1_EAPFASTPROVWAITNOTEDIALOG_CREATEDIALOG_EXIT );
    qDebug("EapFastProvWaitNoteDialog::createDialog EXIT");
}

/*!
 * Destructor.
 */
EapFastProvWaitNoteDialog::~EapFastProvWaitNoteDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_DEAPFASTPROVWAITNOTEDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::~EapFastProvWaitNoteDialog ENTER");
    
    // The dialog widgets are deleted as the dialog is deleted

    qDebug("EapFastProvWaitNoteDialog::~EapFastProvWaitNoteDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_DEAPFASTPROVWAITNOTEDIALOG_EXIT );
}

/*!
 * Function is called when the dialog is about to close
 */
void EapFastProvWaitNoteDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapFastProvWaitNoteDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_CLOSINGDIALOG_EXIT );
}

/*!
 * Device dialog parameters to be set while dialog is displayed.
 * Not supported. 
 *
 * @param [in] parameters NOT USED
 * @return true always.
 */  
bool EapFastProvWaitNoteDialog::setDeviceDialogParameters
                (const QVariantMap &parameters)
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_SETDEVICEDIALOGPARAMETERS_ENTRY );
    
    Q_UNUSED(parameters)
    // changing the dialog after presenting it is not supported.
    
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_SETDEVICEDIALOGPARAMETERS_EXIT );
    return true;
}

/*!
 * Not supported
 *
 * @return 0 always returned.
 */
int EapFastProvWaitNoteDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/*!
 * Dialog is closed and the signal about closing is emitted
 *
 * @param [in] byClient indicates when the user closes the dialog
 */
void EapFastProvWaitNoteDialog::closeDeviceDialog(bool byClient)
{   
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_CLOSEDEVICEDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::closeDeviceDialog ENTER");
        
    Q_UNUSED(byClient)
    
    emit deviceDialogClosed();
    
    qDebug("EapFastProvWaitNoteDialog::closeDeviceDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_CLOSEDEVICEDIALOG_EXIT );
}

/*!
 * This dialog widget is returned to the caller
 *
 * @return this dialog widget
 */
HbPopup *EapFastProvWaitNoteDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::deviceDialogWidget ENTER");
    
    qDebug("EapFastProvWaitNoteDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastProvWaitNoteDialog*>(this);
}

