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
*    Control Panel QT UI for WPA2 only configuration
*
*/

/*
* %version: 10 %
*/


#ifndef CPWPA2UI_H
#define CPWPA2UI_H

// System includes
#include <cpsettingformitemdata.h>
#include <HbMessageBox>
//#include <HbTranslator>
//#include <QSharedPointer>
#include <QTranslator>


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

/*!
 * @addtogroup group_wlan_security_ui_plugin_wpa2_only
 * @{
 */

/*! 
 * Implements WPA2 only plugin for Wlan security control panel  
 */
// Class declaration
class CpWpa2Ui : public QObject, public CpWlanSecurityPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpWlanSecurityPluginInterface)

public:
    CpWpa2Ui();
    ~CpWpa2Ui();

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
 
    //void currentEapPlugin(int currentPlugin);    
    //void wpaTypeChanged(int pskEnable);
    void pskKeyChanged(QString& key);
    

private:
    
    Q_DISABLE_COPY(CpWpa2Ui)
        
    //!WPA security group item
    CpSettingFormItemData* mUi;   

    //! Connection method Id
    int mCmId;
   
    //!Translator for all the localisation Text Id's
    //QSharedPointer<HbTranslator> mTranslator;
    QTranslator* mTranslator;
    
    //! Connection Settings Shim connection method pointer    
    CmConnectionMethodShim *mCmCM;    
    
    //! Eap Plugin config interface
	EapQtConfigInterface *mEapQtConfigInterface;
	
	//!WPA ui Implementer Interface
    QScopedPointer <CpWpaCmnUi> mWpa2Ui;
    
    //! Message box for info notes
    QSharedPointer<HbMessageBox> mMessageBox;

 };

/*! @} */
 
#endif
