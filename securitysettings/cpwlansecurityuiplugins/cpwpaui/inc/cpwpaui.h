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
* Description: .
*    Control Panel QT UI for WPA/WPA2 configuration
*
*/

/*
* %version: tr1cfwln#11.1.1 %
*/


#ifndef CPWPAUI_H
#define CPWPAUI_H

// System includes
#include <cpsettingformitemdata.h>
#include <hbglobal.h>
#include <HbMessageBox>

// User includes
#include "cpwlansecurityplugininterface.h"

// Forward declarations
class EapPluginInformation;
class PluginInformation;
class CpBaseSettingView;
class EapQtConfigInterface;
class EapEntyItemData;
class CpWpaCmnUi;
class CmConnectionMethodShim;
class QTranslator;

/*!
 * @addtogroup group_wlan_security_ui_plugin_wpa/wpa2
 * @{
 */

/*! 
 * Implements WPA/WPA2 plugin for Wlan security control panel  
 */
class CpWpaUi : public QObject, public CpWlanSecurityPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpWlanSecurityPluginInterface)

public:
    CpWpaUi();
    ~CpWpaUi();

public: // from CpWlanSecurityPluginInterface 
       
    CMManagerShim::WlanSecMode securityMode() const;
    
    QString securityModeTextId() const;
        
    void setReference(CmConnectionMethodShim *cmCm, uint id);
        
    int orderNumber() const;
       
    CpSettingFormItemData* uiInstance(
            CpItemDataHelper &dataHelper);
    
private:
    
    bool tryUpdate();

    void handleUpdateError();

    void showMessageBox( HbMessageBox::MessageBoxType type,
            const QString &text);
    
    void updateWpaSettings();
    
  
private slots:
 
    //void currentEapPlugin(int plugin);    
    //void wpaTypeChanged(int pskEnable);
    void pskKeyChanged(QString& key);
         

private:
    
    Q_DISABLE_COPY(CpWpaUi)
        
    //!WPA security group item
    CpSettingFormItemData* mUi;   

    //! Connection method Id
    int mCmId;
   
    //!Translator for all the localisation Text Id's
    QTranslator *mTranslator;
    
    //! Connection Settings Shim connection method pointer    
    CmConnectionMethodShim *mCmCM;    
    
    //! Eap Plugin config interface
    EapQtConfigInterface *mEapQtConfigInterface;
    
    //!WPA ui Implementer Interface
    QScopedPointer <CpWpaCmnUi> mWpaUi;
    
    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;
    
 };

/*! @} */
 
#endif //CPWPAUI_H
