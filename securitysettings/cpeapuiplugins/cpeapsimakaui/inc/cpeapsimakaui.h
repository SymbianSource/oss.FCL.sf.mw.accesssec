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
 *   Control Panel QT UI for EAP-SIM and EAP-AKA method configuration
 *
 */

/*
 * %version:  14 %
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
class HbDataFormModelItem;
class CpSettingFormItemData;
class EapQtValidator;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_simaka
 * @{
 */

class CpEapSimAkaUi : public CpBaseSettingView
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
    void createUi();
    void createUsername();
    void createRealm();
    
    bool checkStateToBool(const int state);
    int boolToCheckState(const bool state);
    
    bool storeSettings();
    bool validate();
    bool validateGroup(CpSettingFormItemData *edit, CpSettingFormItemData *checkBox,
        EapQtValidator* validator);

private slots:
    void setValidator(const QModelIndex);
    void usernameAutomaticChanged(int state);
    void realmAutomaticChanged(int state);

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
    //! Control Panel item data helper for EAP-SIM/AKA plugins
    CpItemDataHelper *mItemDataHelper;
    //! EAP-SIM/AKA settings group
    HbDataFormModelItem *mGroupItem;
    //! Username generate automatically checkBox
    CpSettingFormItemData *mUsernameAutomatic;
    //! Username lineEdit
    CpSettingFormItemData *mUsername;
    //! Realm generate automatically checkBox
    CpSettingFormItemData *mRealmAutomatic;
    //! Realm lineEdit
    CpSettingFormItemData *mRealm;

    //! Realm validator
    QScopedPointer<EapQtValidator> mValidatorRealm;
    //! Username validator
    QScopedPointer<EapQtValidator> mValidatorUsername;
};

/*! @} */

#endif
