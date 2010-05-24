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

#include "eapfastprovwaitnotedialog.h"
#include "OstTraceDefinitions.h"
#include <QGraphicsLinearLayout>
#ifdef OST_TRACE_COMPILER_IN_USE
#endif

/**
 * The constructor
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

    
/**
 * The construction of the dialog
 */ 
void EapFastProvWaitNoteDialog::createDialog(const QVariantMap &parameters )
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_CREATEDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::createDialog ENTER");
    
    QString mainText;    
    QString key = QString("notificationtxt");
    
    bool authProvWaitNote = false;
    
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

/**
 * Destructor
 */
EapFastProvWaitNoteDialog::~EapFastProvWaitNoteDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_DEAPFASTPROVWAITNOTEDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::~EapFastProvWaitNoteDialog ENTER");
    
    // The dialog widgets are deleted as the dialog is deleted

    qDebug("EapFastProvWaitNoteDialog::~EapFastProvWaitNoteDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_DEAPFASTPROVWAITNOTEDIALOG_EXIT );
}

/**
 * Function is called when the dialog is about to close
 * 
 */
void EapFastProvWaitNoteDialog::closingDialog()
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_CLOSINGDIALOG_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::closingDialog ENTER");
 
    closeDeviceDialog(false);
    
    qDebug("EapFastProvWaitNoteDialog::closingDialog EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_CLOSINGDIALOG_EXIT );
}

/**
 * Updating the dialog during its showing is not allowed.
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

/**
 * Not supported, 0 always returned
 */
int EapFastProvWaitNoteDialog::deviceDialogError() const
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGERROR_ENTRY );
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGERROR_EXIT);
    return 0;
}

/**
 * Dialog is closed and the signal about closing is emitted
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

/**
 * This dialog widget is returned to the caller
 */
HbPopup *EapFastProvWaitNoteDialog::deviceDialogWidget() const
{
    OstTraceFunctionEntry0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGWIDGET_ENTRY );
    qDebug("EapFastProvWaitNoteDialog::deviceDialogWidget ENTER");
    
    qDebug("EapFastProvWaitNoteDialog::deviceDialogWidget EXIT");
    OstTraceFunctionExit0( EAPFASTPROVWAITNOTEDIALOG_DEVICEDIALOGWIDGET_EXIT );
    
    return const_cast<EapFastProvWaitNoteDialog*>(this);
}

