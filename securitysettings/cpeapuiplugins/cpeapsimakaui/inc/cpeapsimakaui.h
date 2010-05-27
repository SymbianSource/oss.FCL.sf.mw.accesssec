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
 *   Control Panel QT UI for EAP-SIM and EAP-AKA method configuration
 *
 */

/*
 * %version:  12 %
 */

#ifndef CPEAPSIMAKAUI_H
#define CPEAPSIMAKAUI_H

// System includes
#include <cpbasesettingview.h>
#include <eapqtconfiginterface.h>
#include <eapqtplugininfo.h>
#include <eapqtpluginhandle.h>

// User includes

// Forward declarations
class HbDataForm;
class HbDataFormModel;
class CpSettingFormItemData;
class EapQtValidator;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_simaka
 * @{
 */

class CpEapSimAkaUi: public CpBaseSettingView
{
Q_OBJECT

public:
    CpEapSimAkaUi(
        const EapQtConfigInterface::EapBearerType bearer,
        const int iapId,
        const EapQtPluginInfo &plugin,
        const EapQtPluginHandle& outerHandle);
    ~CpEapSimAkaUi();

protected:
    void close();
    
private:
    void initializeSimAkaUi();
    bool checkStateToBool(const int state);
    int boolToCheckState(const bool state);
    void storeSettings();
    bool validate();
    bool validateGroup(CpSettingFormItemData *edit, CpSettingFormItemData *checkBox,
        EapQtValidator* validator);

private slots:
    void setValidator(const QModelIndex);
    void usernameAutomaticChanged(int state);
    void realmAutomaticChanged(int state);

private:
    QScopedPointer <EapQtConfigInterface> mConfigIf;
    EapQtPluginInfo mPluginInfo;
    EapQtPluginHandle mOuterHandle;
    HbDataForm *mForm;
    HbDataFormModel *mModel;
    CpSettingFormItemData *mUsernameAutomatic;
    CpSettingFormItemData *mUsername;
    CpSettingFormItemData *mRealmAutomatic;
    CpSettingFormItemData *mRealm;

    QScopedPointer<EapQtValidator> mValidatorRealm;
    QScopedPointer<EapQtValidator> mValidatorUsername;
};

/*! @} */

#endif
