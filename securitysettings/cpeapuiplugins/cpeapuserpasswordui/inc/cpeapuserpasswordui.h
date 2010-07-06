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
 *   Control Panel QT UI for username-password based EAP method configuration
 *
 */

/*
 * %version: 21 %
 */

#ifndef CPEAPUSERPASSWORDUI_H
#define CPEAPUSERPASSWORDUI_H

// System includes
#include <cpbasesettingview.h>
#include <eapqtplugininfo.h>
#include <eapqtpluginhandle.h>
#include <eapqtconfiginterface.h>

// User includes

// Forward declarations
class HbDataForm;
class HbDataFormModel;
class HbDataFormModelItem;
class CpSettingFormItemData;
class HbLineEdit;
class EapQtValidator;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_userpassword
 * @{
 */

class CpEapUserPasswordUi : public CpBaseSettingView
{
Q_OBJECT

public:
    CpEapUserPasswordUi(
        const EapQtConfigInterface::EapBearerType bearer,
        const int iapId,
        const EapQtPluginInfo &plugin,
        const EapQtPluginHandle& outerHandle);
    ~CpEapUserPasswordUi();

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void close();
    
private:
    void createUi();
    void createUsername();
    void createPassword();
    
    bool checkStateToBool(const int state);
    int boolToCheckState(const bool state);
    
    bool storeSettings();
    bool validate();
    bool validateUsername();
    bool validatePasswordGroup();
    
private slots:
    void setValidator(const QModelIndex);
    void passwordPromptChanged(int state);
    void passwordChanged();
    
private:
    //! Pointer to EapQtConfigInterface
    QScopedPointer <EapQtConfigInterface> mConfigIf;
    //! Plugin info
    EapQtPluginInfo mPluginInfo;
    //! Outer handle
    EapQtPluginHandle mOuterHandle;
    //! Current EAP configuration
    EapQtConfig mEapConfig;
    
    //! Dataform
    HbDataForm *mForm;
    //! Datform model
    HbDataFormModel *mModel;
    //! Control Panel item data helper for username-password plugins
    CpItemDataHelper *mItemDataHelper;
    //! Username-password settings group
    HbDataFormModelItem *mGroupItem;
    //! Username lineEdit
    CpSettingFormItemData *mUsername;
    //! Prompt password checkBox
    CpSettingFormItemData *mPasswordPrompt;
    //! Password lineEdit
    CpSettingFormItemData *mPassword;

    //! Realm validator
    QScopedPointer<EapQtValidator> mValidatorUsername;
    //! Password validator
    QScopedPointer<EapQtValidator> mValidatorPassword;
    
    //! Password is stored
    bool mPasswordStored;
    //! Password is saved
    bool mPasswordChanged;
    //! Password lineEdit
    HbLineEdit *mPasswordEdit;
        
};

/*! @} */

#endif
