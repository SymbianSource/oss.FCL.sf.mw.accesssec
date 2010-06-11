/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of the License "Eclipse Public License v1.0"
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
 * %version: 18 %
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
class CpSettingFormItemData;
class HbLineEdit;
class EapQtValidator;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_userpassword
 * @{
 */

class CpEapUserPasswordUi: public CpBaseSettingView
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
    void initializeUserPasswordUi();
    bool checkStateToBool(const int state);
    int boolToCheckState(const bool state);
    void storeSettings();
    bool validate();
    bool validatePasswordGroup();
    
private slots:
    void setValidator(const QModelIndex);
    void passwordPromptChanged(int state);
    void passwordChanged();
    
private:
    QScopedPointer <EapQtConfigInterface> mConfigIf;
    EapQtPluginInfo mPluginInfo;
    EapQtPluginHandle mOuterHandle;
    HbDataForm *mForm;
    HbDataFormModel *mModel;
    CpSettingFormItemData *mUsername;
    CpSettingFormItemData *mPasswordPrompt;
    CpSettingFormItemData *mPassword;

    QScopedPointer<EapQtValidator> mValidatorUsername;
    QScopedPointer<EapQtValidator> mValidatorPassword;
    
    bool mPasswordStored;
    bool mPasswordChanged;
    HbLineEdit *mPasswordEdit;
        
};

/*! @} */

#endif
