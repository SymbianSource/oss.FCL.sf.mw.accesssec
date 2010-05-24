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
#ifndef __EAPFASTINSTALLQUERYDIALOG_H__
#define __EAPFASTINSTALLQUERYDIALOG_H__

#include <HbTranslator>
#include <HbMessageBox>
#include <HbAction>
#include <hbdevicedialoginterface.h>

class EapQtValidator;

class EapFastInstallPacQueryDialog: public HbMessageBox, public HbDeviceDialogInterface
    {
    Q_OBJECT

    public:
        /* Constructor */
        EapFastInstallPacQueryDialog(const QVariantMap &parameters);
        /* Destructor */
        ~EapFastInstallPacQueryDialog();
        
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
        /* Slot that is mapped to the Yes Action button's triggered signal */
        void yesPressed();
        
        /* Slot that is mapped to the No Action button's triggered signal */
        void noPressed();
        
        /* Slot that is mapped to the signal that indicates to closing of the dialog */
        void closingDialog();
               
    private:
                
        Q_DISABLE_COPY(EapFastInstallPacQueryDialog)
   
    private:
        /* Pointer to the Yes action button */
        HbAction* mActionYes;
        
        /* Pointer to the HbTranslator */
        QScopedPointer<HbTranslator> mTranslator;
        
        /* Tells whether close has already been called for the dialog */
        bool mClose;
        
        /* Tells whether Yes Action has already been pressed */
        bool mYesActionPressed;
    };

#endif // __EAPFASTINSTALLQUERYDIALOG_H__
