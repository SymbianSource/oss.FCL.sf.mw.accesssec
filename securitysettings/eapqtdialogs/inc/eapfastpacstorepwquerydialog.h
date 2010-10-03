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
* Description: EAP-FAST PAC Store Password Query Dialog
*
*/

/*
* %version: 5 %
*/

#ifndef __EAPFASTPACSTOREPWQUERYDIALOG_H__
#define __EAPFASTPACSTOREPWQUERYDIALOG_H__

// System includes
#include <HbInputDialog>
#include <hbdevicedialoginterface.h>

// User includes

// Forward declarations
class HbTranslator;


// External data types

// Constants

/*!
   @addtogroup group_eap_fast_pac_store_pwd_query_dialog
   @{
 */

// Class declaration

class EapFastPacStorePwQueryDialog: public HbInputDialog, public HbDeviceDialogInterface
    {
    Q_OBJECT

    public:
        /* Constructor */
        EapFastPacStorePwQueryDialog(const QVariantMap &parameters);
        /* Destructor */
        ~EapFastPacStorePwQueryDialog();
        
        /* Function creates the actual dialog widget. */
        void createDialog();
        
        /* Device dialog parameters to be set while dialog is displayed.
         * Not supported. (from HbDeviceDialogInterface)
         */
        bool setDeviceDialogParameters(const QVariantMap &parameters);
        
        /* Not supported. (from HbDeviceDialogInterface) */
        int deviceDialogError() const;
        
        /* Closes the device dialog. (from HbDeviceDialogInterface)*/
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
                
        /* Slot that is mapped to the Cancel Action button's triggered signal */
        void cancelPressed();
        
        /* Slot that is mapped to the signal that indicates to closing of the dialog */
        void closingDialog();
               
    private:
         
        Q_DISABLE_COPY(EapFastPacStorePwQueryDialog)
   
    private: // data
        // NOT OWNED
        //! Pointer to the line edit object
        HbLineEdit *mEdit;
                
        // OWNED        
                
        //! Pointer to the HbTranslator
        QScopedPointer<HbTranslator> mTranslator;
        
        //! Pointer to the error message HbTranslator
        QScopedPointer<HbTranslator> mErrMsgTranslator;
        
        //! Tells whether close has already been called for the dialog
        bool mClose;
        
    };

/*! @} */

#endif // __EAPFASTPACSTOREPWQUERYDIALOG_H__

