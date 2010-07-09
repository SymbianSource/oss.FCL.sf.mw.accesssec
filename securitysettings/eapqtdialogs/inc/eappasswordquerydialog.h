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
* Description: EAP Password Query Dialog
*
*/

/*
* %version: 4 %
*/

#ifndef __EAPPASSWORDQUERYDIALOG_H__
#define __EAPPASSWORDQUERYDIALOG_H__


// System includes
#include <HbInputDialog>
#include <hbdevicedialoginterface.h>

// User includes

// Forward declarations
class HbTranslator;
class HbLineEdit;
class EapQtValidator;

// External data types

// Constants

/*!
   @addtogroup group_eap_password_query_dialog
   @{
 */

// Class declaration

class EapPasswordQueryDialog: public HbInputDialog, public HbDeviceDialogInterface
    {
    Q_OBJECT

    public:
        /* Constructor */
        EapPasswordQueryDialog(const QVariantMap &parameters);
        /* Destructor */
        ~EapPasswordQueryDialog();
        
        /* Function creates the actual dialog widget */
        void createDialog( const QVariantMap &parameters );
        
        /* Device dialog parameters to be set while dialog is displayed.
         * Not supported. (from HbDeviceDialogInterface)
         */
        bool setDeviceDialogParameters(const QVariantMap &parameters);
        
        /* Not supported. (from HbDeviceDialogInterface)*/
        int deviceDialogError() const;
        
        /* Closes the device dialog. (from HbDeviceDialogInterface) */
        void closeDeviceDialog(bool byClient);
        
        /* Returns a pointer to this dialog widget.
           (from HbDeviceDialogInterface)*/
        HbPopup *deviceDialogWidget() const;
                
    signals:
        /* Signal is emitted when the dialog is closed */
        void deviceDialogClosed();
    
        /* Data is emitted in QVariantMap when Ok Action button is selected */
        void deviceDialogData(QVariantMap data);
        
    private slots:
        /* Slot that is mapped to the Ok Action button's triggered signal */
        void okPressed();
                
        /* Slot that is mapped to the Cancel Action button's triggered signal */
        void cancelPressed();
        
        /* Slot that is mapped to the signal that indicates to closing of the dialog */
        void closingDialog();
                
    private:
        
        bool validate() const;
        
        Q_DISABLE_COPY(EapPasswordQueryDialog)
   
    private: //data
        // NOT OWNED
        //! Pointer to the line edit 1 object
        HbLineEdit *mEdit;
        
        // OWNED           
        //! Pointer to the password validator object
        QScopedPointer<EapQtValidator> mPwdValidator;
        
        //! Pointer to the main HbTranslator
        QScopedPointer<HbTranslator> mTranslator;
                
        //! Tells whether close has already been called for the dialog */
        bool mClose;
        
        //! Tells whether Ok Action has already been pressed
        bool mOkActionPressed;
    };

/*! @} */

#endif // __EAPPASSWORDQUERYDIALOG_H__

