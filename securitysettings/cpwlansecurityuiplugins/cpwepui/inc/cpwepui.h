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
 *    Control Panel QT UI for WEP configuration
 *
 */

/*
 * %version: 13 %
 */

#ifndef CPWEPUI_H
#define CPWEPUI_H

// System includes
#include <cpsettingformitemdata.h>
#include <QStringList>
#include <HbMessageBox>
//#include <HbTranslator>
//#include <QSharedPointer>
#include <QTranslator>

//User Includes
#include "cpwlansecurityplugininterface.h"
#include "wlansecuritycontrolpanelwepdefs.h"
#include "wepkeyvalidator.h"

// Forward declarations
class QTranslator;
class CmConnectionMethodShim;
class CpWepKeyValidation;
/*!
 * @addtogroup group_wlan_security_ui_plugin_wep
 * @{
 */

/*! 
 * Implements WEP plugin for Wlan security control panel  
 */

// Class declaration
class CpWepUi : public QObject, public CpWlanSecurityPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpWlanSecurityPluginInterface)

public:
    CpWepUi();
    ~CpWepUi();

public:
    // from CpWlanSecurityPluginInterface 

    CMManagerShim::WlanSecMode securityMode() const;

    QString securityModeTextId() const;
    
    void setReference(CmConnectionMethodShim *cmCm, uint id);
    
    int orderNumber() const;
    
    CpSettingFormItemData* uiInstance(CpItemDataHelper &dataHelper);

public:

    enum WEPKeyFormat
        {
        EFormatHex, EFormatAscii,
        };

private:

    void loadFieldsFromDataBase();

    void wepKeyTextChanged(int index);

    bool tryUpdate();

    void handleUpdateError();

    void showMessageBox(HbMessageBox::MessageBoxType type,
            const QString &text);

    void updateWepSettings();

    void commitWEPkeys(int index);
    
    void createWEPKeyOneGroup(CpItemDataHelper &dataHelpper);
    
    void createWEPKeyTwoGroup(CpItemDataHelper &dataHelpper);
    
    void createWEPKeyThreeGroup(CpItemDataHelper &dataHelpper);
    
    void createWEPKeyFourGroup(CpItemDataHelper &dataHelpper); 
    
    void storeWEPKey(CMManagerShim::ConnectionMethodAttribute enumValue,QString& key);
    
    void setKeyFormat(QString& key,int index);
        
    CMManagerShim::ConnectionMethodAttribute getWEPKeyEnum(int index);
    
private slots:

    void wepKeyInUseChanged(int index);

    void wepKeyOneChanged();

    void wepKeyTwoChanged();

    void wepKeyThreeChanged();

    void wepKeyFourChanged();

private:

    Q_DISABLE_COPY(CpWepUi)

    //!WEP security group item
    CpSettingFormItemData* mUi;

    //! Store strings of WEP keys
    QStringList mKeyData;

    //! WEP keys item
    CpSettingFormItemData *mWepKey[KMaxNumberofKeys];

    //! WEP keys text item
    CpSettingFormItemData *mWepKeyText[KMaxNumberofKeys];

    //!Store the index of the current key in use   
    int mNewKeySelected;

    //QSharedPointer<HbTranslator> mTranslator;
    QTranslator* mTranslator;

    //! Connection Settings Shim connection method pointer
    CmConnectionMethodShim *mCmCM;

    //! Connection method Id
    int mCmId;

    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;

    //! Store Formats of WEP keys
    WEPKeyFormat mkeyFormat[KMaxNumberofKeys];
    
    

};

/*! @} */

#endif //CPWEPUI_H
