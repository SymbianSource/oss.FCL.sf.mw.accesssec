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
 *   Control Panel QT UI for PAC store configuration
 *
 */

/*
 * %version: 5 %
 */

#ifndef CPEAPPACSTOREUI_H
#define CPEAPPACSTOREUI_H

// System includes
#include <HbMessageBox>
#include <cpbasesettingview.h>
#include <cpsettingformitemdata.h>
#include <eapqtconfiginterface.h>

// User includes

// Forward declarations
class HbDataFormModelItem;
class HbMessageBox;
class HbInputDialog;
class EapQtValidator;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_eap_tlsmethods
 * @{
 */
// Class declaration
class CpEapPacStoreUi : public CpSettingFormItemData
{
Q_OBJECT

public:
    CpEapPacStoreUi(EapQtConfigInterface *configIf);
    ~CpEapPacStoreUi();

    CpSettingFormItemData* uiInstance(
        CpItemDataHelper &dataHelper);

signals:

public slots:

protected:

protected slots:

private:
    enum PacStorePasswordIndexes {
        PacStorePasswordPrompt,
        PacStorePasswordUserDefined
    };
    
private:
    void createPacStorePassword();
    void createResetPacStore();

    void setPacStorePasswordState(const PacStorePasswordIndexes state);

    void showExistPasswordQuery();
    void showNewPasswordQuery();
    void showMessageBox(
        HbMessageBox::MessageBoxType type,
        const QString &text);

private slots:  
    void pacStorePasswordChanged(int value);
    void resetPacStoreButtonPressed(
        QPersistentModelIndex index, 
        QVariant value);

    void clearPacStorePasswordConfirmed(int action);
    void resetPacStoreConfirmed(int action);

    void completeExistPasswordQuery();
    void completeNewPasswordQuery();
    void cancelPasswordQuery();
    void invalidPasswordInfoClosed(int action);

private:
    //! Pointer to EapQtConfigInterface
    EapQtConfigInterface *mConfigIf;
    //! Control Panel item data helper
    CpItemDataHelper *mItemDataHelper;
    //! PAC store configuration
    EapQtPacStoreConfig mPacStoreConfig;
    
    //! PAC store group item
    QScopedPointer<CpSettingFormItemData> mPacStoreGroup;
    //! PAC store password comboBox
    CpSettingFormItemData *mPacStorePassword;
    //! Reset PAC store button
    CpSettingFormItemData *mResetPacStore;

    //! Validator for PAC store password
    QScopedPointer<EapQtValidator> mValidatorPacStore;
    
    //! State of PAC store password (prompt/user defined)
    int mPacStorePasswordState;
    //! PAC store password query dialog
    HbInputDialog *mExistPasswordDialog;
    //! New PAC store password query dialog
    HbInputDialog *mNewPasswordDialog;
    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;
};

/*! @} */

#endif
