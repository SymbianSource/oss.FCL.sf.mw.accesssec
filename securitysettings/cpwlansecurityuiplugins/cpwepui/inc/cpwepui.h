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
 *    Control Panel QT UI for WEP configuration
 *
 */

/*
 * %version: tr1cfwln#18 %
 */

#ifndef CPWEPUI_H
#define CPWEPUI_H

// System includes
#include <cpsettingformitemdata.h>
#include <QStringList>
#include <HbMessageBox>
#include <cpwlansecurityplugininterface.h>

//User Includes

// Forward declarations
class CmConnectionMethodShim;
class HbTranslator;
class WepKeyValidator;

//Constant declarations
//!Maximum Number of Keys for WEP
static const int KMaxNumberofKeys =  4;

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
    
    bool validateSettings();

private:

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
    
    void createWEPKeyGroup(int index);
    
    void addConnections(CpItemDataHelper &dataHelpper);
    
private slots:

    void wepKeyInUseChanged(int index);

    void wepKeyOneChanged();

    void wepKeyTwoChanged();

    void wepKeyThreeChanged();

    void wepKeyFourChanged();
    
    void setEditorPreferences(const QModelIndex &modelIndex);

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
   
    //!Translator for all the localisation Text Id's
    HbTranslator* mTranslator;

    //!Connection Settings Shim connection method pointer
    CmConnectionMethodShim *mCmCM;

    //! Connection method Id
    int mCmId;

    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;

    //! Store Formats of WEP keys
    WEPKeyFormat mkeyFormat[KMaxNumberofKeys];
        
    CpItemDataHelper* mItemDataHelper;
    
    

};

/*! @} */

#endif //CPWEPUI_H
