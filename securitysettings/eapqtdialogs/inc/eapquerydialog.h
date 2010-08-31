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
* Description: EAP Challenge query Dialog
*
*/

/*
 * %version: 3 %
 */
 
#ifndef __EAPQUERYDIALOG_H__
#define __EAPQUERYDIALOG_H__

// System includes
#include <HbMessageBox>
#include <hbdevicedialoginterface.h>

// User includes

// Forward declarations
class HbTranslator;
class EapQtValidator;

// External data types

// Constants

/*!
   @addtogroup group_query_dialog
   @{
 */

// Class declaration

class EapQueryDialog: public HbMessageBox, public HbDeviceDialogInterface
    {
    Q_OBJECT

    public:
        /* Constructor */
        EapQueryDialog(const QVariantMap &parameters);
        /* Destructor */
        ~EapQueryDialog();
        
        /* Function creates the actual dialog widget */
        void createDialog(const QVariantMap &parameters );
        
        /* Device dialog parameters to be set while dialog is displayed.
         * Not supported. (from HbDeviceDialogInterface)
         */
        bool setDeviceDialogParameters(const QVariantMap &parameters);
        
        /* Not supported. (from HbDeviceDialogInterface) */
        int deviceDialogError() const;
        
        /* Closes the device dialog. (from HbDeviceDialogInterface) */
        void closeDeviceDialog(bool byClient);
        
        /* Returns a pointer to this dialog widget.
           (from HbDeviceDialogInterface) */
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
                
        Q_DISABLE_COPY(EapQueryDialog)
   
    private: // data
        // NOT OWNED
        
        // OWNED      
        //! Pointer to the HbTranslator
        QScopedPointer<HbTranslator> mTranslator;
        
        //! Tells whether Ok Action has already been pressed
        bool mOkActionPressed;
    };
    
/*! @} */

#endif // __EAPQUERYDIALOG_H__
