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
* Description: 
*
*/
#ifndef __EAPFASTPROVNOTSUCCESSNOTEDIALOG_H__
#define __EAPFASTPROVNOTSUCCESSNOTEDIALOG_H__

#include <HbAction>
#include <HbMessageBox>
#include <HbTranslator>
#include <hbdevicedialoginterface.h>


class EapFastProvNotSuccessNoteDialog: public HbMessageBox, public HbDeviceDialogInterface
    {
    Q_OBJECT

    public:
        /* Constructor */
        EapFastProvNotSuccessNoteDialog(const QVariantMap &parameters);
        /* Destructor */
        ~EapFastProvNotSuccessNoteDialog();
        
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
        /* Slot that is mapped to the Ok Action button's triggered signal */
        void okPressed();
        
        /* Slot that is mapped to the signal that indicates to closing of the dialog */
        void closingDialog();
               
    private:
                
        Q_DISABLE_COPY(EapFastProvNotSuccessNoteDialog)
   
    private:
        /* Pointer to the Ok action button */
        HbAction* mActionOk;
        
        /* Pointer to the HbTranslator */
        QScopedPointer<HbTranslator> mTranslator;
                
        /* Tells whether Ok Action has already been pressed */
        bool mOkActionPressed;
    };

#endif // __EAPFASTPROVNOTSUCCESSNOTEDIALOG_H__
