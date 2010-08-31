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
 *    Control Panel QT UI for WPA2 only configuration
 *
 */

/*
* %version: tr1cfwln#15 %
*/


#ifndef CPWPA2UI_H
#define CPWPA2UI_H

// System includes
#include <cpsettingformitemdata.h>
#include <cpwlansecurityplugininterface.h>

// User includes


// Forward declarations
class EapQtConfigInterface;
class CpWpaCmnUi;
class CmConnectionMethodShim;
class HbTranslator;


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
       
       bool validateSettings();

private:
    
    Q_DISABLE_COPY(CpWpa2Ui)
        
    //!WPA security group item
    CpSettingFormItemData* mUi;  
    
    //!Translator for all the localisation Text Id's    
   	HbTranslator* mTranslator;

    //! Connection Settings Shim connection method pointer    
    CmConnectionMethodShim *mCmCM;    
    
    //! Eap Plugin config interface
	EapQtConfigInterface *mEapQtConfigInterface;
	
	//!WPA ui Implementer Interface
    QScopedPointer <CpWpaCmnUi> mWpa2Ui;

 };

/*! @} */
 
#endif
