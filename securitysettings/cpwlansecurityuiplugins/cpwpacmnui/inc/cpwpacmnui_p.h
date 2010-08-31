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
 *    Private Implementation for Control Panel QT UI for WPA/WPA2/802_Dot_1x configuration
 *
 */

/*
 * %version: tr1cfwln#7 %
 */

#ifndef CPWPACMNUI_P_H_
#define CPWPACMNUI_P_H_

// System includes
#include <HbMessageBox>
#include <cmmanagerdefines_shim.h>

// User includes

// Forward declarations
class CpItemDataHelper;
class CpSettingFormItemData;
class EapQtConfigInterface;
class CmConnectionMethodShim;
class EapEntryItemData;
class CpBaseSettingView;
class EapQtPluginInfo;

//class declaration
class CpWpaCmnUiPrivate :public QObject
    { 
    Q_OBJECT  
public:

    CpWpaCmnUiPrivate(CMManagerShim::WlanSecMode securityMode,
            CpItemDataHelper &dataHelpper);
    ~CpWpaCmnUiPrivate();

    CpSettingFormItemData* createUi(
            EapQtConfigInterface *mEapQtConfigInterface,
            CmConnectionMethodShim *cmCM);
    
    CpBaseSettingView *eapUiInstance();
    
    bool validateSettings();

private:
    
    
    CpSettingFormItemData* createWpaTypeSelector();
    CpSettingFormItemData* createPskEditor();
    CpSettingFormItemData* createEapSelector();
    EapEntryItemData* createEapEntryItem();
    CpSettingFormItemData *createUnencryptedBox();
    void removeObjectFromView(CpSettingFormItemData *&object);

    void loadWPAPskView();
    void loadWPAEapView();       
    void loadUi();
    void loadWPA_WPA2Fields();
    void load802Dot1xFields(); 
    void loadEapConfigurations();
    
    void readValues();
        
    bool tryUpdate();
    void handleUpdateError();
    void showMessageBox(
        HbMessageBox::MessageBoxType type,
        const QString &text);      
   
    void updateWpaType(int pskEnable);
    void updatePskKey(QString& key);
    
    void reset();  

private slots:

    void wpaTypeChanged(int pskEnable);
    void pskKeyChanged();
    void eapTypeChanged(int eapPlugin);
    void unencryptConnStateChanged(int state);
    
    static bool pluginLessThan(
        const EapQtPluginInfo &plugin1,
        const EapQtPluginInfo &plugin2);

    void setEditorPreferences(const QModelIndex &modelIndex);

private:
    Q_DISABLE_COPY(CpWpaCmnUiPrivate)
    
    //!Data Helper from CpWlan Interface
    CpItemDataHelper &mDataHelper;
    
    //!Parent element encompassing all the Ui Setting Items   
    CpSettingFormItemData *mCmnUi;
    
    //!ui element for Pre-Shared Key
    CpSettingFormItemData *mPskKeyText;
    
    /*!ui element ,holding the list of EAP plugins 
     * from which the user can choose
     */
    CpSettingFormItemData *mEapPlugins;
    
    /*!ui element to hold Encrypted Connection flag status, 
     * for 802.1x mode
     */
    CpSettingFormItemData *mUnencryptedConnection;
    
    //!Opens a separate View for the EAPmode chosen 
    CpSettingFormItemData *mWpaEapItem;
    
    //!Stores the Pre-Shared key value entered
    QString mKeyData;
    
    //!List hthe EAP plugins
    QList<EapQtPluginInfo> mPlugins;
    
    //!Pointer to API that returns the Ui instance for the EAP plugin 
    EapEntryItemData *mEapEntry;
    
    //!Pointer to EAP interface 
    EapQtConfigInterface *mEapQtConfigInterface;
    
    //!Current mode chosen
    CMManagerShim::WlanSecMode mSecurityMode;   
    
    //! Connection Settings Shim connection method pointer    
    CmConnectionMethodShim* mConnMethod;
    
    //!Flag to indicate if its the EAP/PSK mode
    bool mEnablePskMode;
    
    //!The current EAP method chosen 
    int mCurrentEapPlugin;
    
    //!Flag to indicate if Unecrypted Connection is enabled 
   	bool mUnencryptState;

    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;

    };

#endif /* CPWPACMNUI_P_H_ */
