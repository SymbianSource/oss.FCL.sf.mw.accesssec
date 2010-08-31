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
 *    Control Panel QT UI for WPA/WPA2 configuration
 *
 */

/*
* %version: tr1cfwln#17 %
*/


#ifndef CPWPAUI_H
#define CPWPAUI_H

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
    
    bool validateSettings();
    

private:
    
    Q_DISABLE_COPY(CpWpaUi)
        
    //!WPA security group item
    CpSettingFormItemData* mUi;   

    //!Translator for all the localisation Text Id's
    HbTranslator *mTranslator;
    
    //! Connection Settings Shim connection method pointer    
    CmConnectionMethodShim *mCmCM;    
    
    //! Eap Plugin config interface
    EapQtConfigInterface *mEapQtConfigInterface;
    
    //!WPA ui Implementer Interface
    QScopedPointer <CpWpaCmnUi> mWpaUi;
    
 };

/*! @} */
 
#endif //CPWPAUI_H
