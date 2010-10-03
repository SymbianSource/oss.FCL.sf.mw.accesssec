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
 * %version: tr1cfwln#20 %
 */

#ifndef CPWEPUI_H
#define CPWEPUI_H

// System includes
#include <cpsettingformitemdata.h>
#include <QStringList>
#include <HbMessageBox>
#include <cpwlansecurityplugininterface.h>

// User Includes

// Forward declarations
class CmConnectionMethodShim;
class HbTranslator;
class WepKeyValidator;

// Constants

//!Maximum Number of Keys for WEP
static const int KMaxNumberofKeys =  4;

/*! 
 * Implements WEP plugin for Wlan security control panel  
 */

// Class declaration
class CpWepUi : public CpSettingFormItemData
{
    Q_OBJECT

public: // CpWepUi public methods
    
    CpWepUi(
        CpItemDataHelper* dataHelper,
        CmConnectionMethodShim* cmCM );
    
    ~CpWepUi();
    
    bool validateSettings();

signals:

public slots:

protected:

protected slots:
    
private: // CpWepUi private definitions

    enum WEPKeyFormat
        {
        EFormatHex, EFormatAscii,
        };

private: // CpWepUi private methods

    void createUi();
    
    void loadFieldsFromDataBase();

    void wepKeyTextChanged(int index);

    bool tryUpdate();

    void handleUpdateError();

    void showMessageBox(HbMessageBox::MessageBoxType type,
            const QString &text);

    void updateWepSettings();

    void commitWEPkeys(int index);
    
    void createWEPKeyOneGroup(CpItemDataHelper &dataHelper);
    
    void createWEPKeyTwoGroup(CpItemDataHelper &dataHelper);
    
    void createWEPKeyThreeGroup(CpItemDataHelper &dataHelper);
    
    void createWEPKeyFourGroup(CpItemDataHelper &dataHelper); 
    
    void storeWEPKey(CMManagerShim::ConnectionMethodAttribute enumValue,QString& key);
    
    void setKeyFormat(QString& key,int index);
        
    CMManagerShim::ConnectionMethodAttribute getWEPKeyEnum(int index);
    
    void createWEPKeyGroup(int index);
    
    void addConnections(CpItemDataHelper* dataHelper);
    
private slots:

    void wepKeyInUseChanged(int index);

    void wepKeyOneChanged();

    void wepKeyTwoChanged();

    void wepKeyThreeChanged();

    void wepKeyFourChanged();
    
    void setEditorPreferences(const QModelIndex &modelIndex);

private: // CpWepUi private members

    Q_DISABLE_COPY(CpWepUi)

    //! Store strings of WEP keys
    QStringList mKeyData;

    //! WEP keys item
    CpSettingFormItemData *mWepKey[KMaxNumberofKeys];

    //! WEP keys text item
    CpSettingFormItemData *mWepKeyText[KMaxNumberofKeys];

    //!Store the index of the current key in use   
    int mNewKeySelected;

    //!Connection Settings Shim connection method pointer
    CmConnectionMethodShim *mCmCM;

    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;

    //! Store Formats of WEP keys
    WEPKeyFormat mkeyFormat[KMaxNumberofKeys];
        
    CpItemDataHelper* mItemDataHelper;

};

/*! @} */

#endif //CPWEPUI_H
