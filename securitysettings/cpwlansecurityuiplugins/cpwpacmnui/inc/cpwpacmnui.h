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
 *    Control Panel QT UI for WPA/WPA2/802_Dot_1x configuration
 *
 */

/*
 * %version: 9 %
 */

#ifndef CPWPACMNUI_H
#define CPWPACMNUI_H

// System includes
#include <cpsettingformitemdata.h>
#include <cpsettingformentryitemdata.h>
#include <eapqtconfiginterface.h>
#include <eapqtplugininfo.h>
#include <cpitemdatahelper.h>
#include <cpbasesettingview.h>

// User includes
#include "cpwpacmnui_global.h"
#include "cpwlansecurityplugininterface.h"

// Forward declarations
class EapPluginInformation;
class PluginInformation;
class CpBaseSettingView;
class EapQtConfigInterface;
class EapEntyItemData;
class CmConnectionMethodShim;

/*! 
 * Implements the Ui for WPA/WPA2/802.1x Security Mode  
 */

// Class declaration
class WPAUI_EXPORT CpWpaCmnUi : public QObject
{
    Q_OBJECT
    
    
    public:
    
        CpWpaCmnUi(CMManagerShim::WlanSecMode securityMode, CpItemDataHelper &dataHelpper);
        ~CpWpaCmnUi();
        CpSettingFormItemData* createUi(
                EapQtConfigInterface *mEapQtConfigInterface,
                CmConnectionMethodShim *cmCM);
        //CpBaseSettingView *eapUiInstance();
        
        void reset();

    signals:
    
        void keyChanged(QString& key);
        void pskEapModeToggled(int pskEnable);
        void eapPluginChanged(int eapPlugin);
        void connectionStateChanged(int state);
        
    
    private:
    
        //void loadWPAPskView();
        //void loadWPAEapView();
        //void removePskView();
        //void removeEapView();
        void loadUi();
        void readValues();
        void loadWPA_WPA2Fields();
        //void load802Dot1xFields();
    
    private slots:
    
        //void wpaTypeChanged(int pskEnable);
        void pskKeyChanged();
        //void eapTypeChanged(int eapPlugin);
        //void unencryptConnStateChanged(int state);
    
    private:
        
        Q_DISABLE_COPY(CpWpaCmnUi)
        CpSettingFormItemData* mCmnUi;
        CpItemDataHelper &mDataHelper;
        CpSettingFormItemData* mPskKeyText;
        CpSettingFormItemData* mEapPlugins;
        CpSettingFormItemData* mUnencryptedConnection;
        CpSettingFormItemData *mWpaEapItem;
        QString mKeyData;
        //QList<EapQtPluginInfo> mPlugins;
        EapEntyItemData* mEapEntry;
        EapQtConfigInterface *mEapQtConfigInterface;
        int mPluginCurrent;
        CMManagerShim::WlanSecMode mSecurityMode;
        bool mEnablePskMode;
        int mcurrentEapPlugin;
        CmConnectionMethodShim* mConnMethod;
        int unencryptStateChanged;
};



#endif//CPWPACMNUI_H
