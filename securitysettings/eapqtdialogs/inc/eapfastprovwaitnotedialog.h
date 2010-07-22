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
* Description: Fast Provisioning Wait Notification Dialog
*
*/

/*
* %version: 2 %
*/

#ifndef __EAPFASTPROVWAITNOTEDIALOG_H__
#define __EAPFASTPROVWAITNOTEDIALOG_H__

#include <HbNotificationDialog>
#include <hbdevicedialoginterface.h>

class HbTranslator;

class EapFastProvWaitNoteDialog: public HbNotificationDialog, public HbDeviceDialogInterface
    {
    Q_OBJECT

    public:
        /* Constructor */
        EapFastProvWaitNoteDialog(const QVariantMap &parameters);
        
        /* Destructor */
        ~EapFastProvWaitNoteDialog();
        
        /* Function creates the actual dialog widget */
        void createDialog(const QVariantMap &parameters );
        
        /* Device dialog parameters to be set while dialog is displayed.
         * Not supported.
         */
        bool setDeviceDialogParameters(const QVariantMap &parameters);
        
        /* Not supported */
        int deviceDialogError() const;
        
        /* Closes the device dialog */
        void closeDeviceDialog(bool byClient);
        
        /* Returns a pointer to this dialog widget */
        HbPopup *deviceDialogWidget() const;
                
    signals:
        /* Signal is emitted when the dialog is closed */
        void deviceDialogClosed();
        
        /* Data is emitted in QVariantMap when Ok Action button is selected */
        void deviceDialogData(QVariantMap data);
            
    private slots:
        
        /* Slot that is mapped to the signal that indicates to closing of the dialog */
        void closingDialog();
               
    private:
                
        Q_DISABLE_COPY(EapFastProvWaitNoteDialog)
        
        /* Pointer to the HbTranslator */
        QScopedPointer<HbTranslator> mTranslator;
   
    };

#endif // __EAPFASTPROVWAITNOTEDIALOG_H__
