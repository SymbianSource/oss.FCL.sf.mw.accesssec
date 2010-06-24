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
 *    Control Panel QT UI for 802_Dot_1x configuration
 *
 */

/*
 * %version: tr1cfwln#7 %
 */

#ifndef CP802DOT1XUI_H
#define CP802DOT1XUI_H

// System includes
#include <cpsettingformitemdata.h>
#include <cpwlansecurityplugininterface.h>

// User includes


// Forward declarations
class EapQtConfigInterface;
class CmConnectionMethodShim;
class CpWpaCmnUi;
class HbTranslator;

/*!
 * @addtogroup group_wlan_security_ui_plugin_802_Dot_1x
 * @{
 */

/*! 
 * Implements 802_Dot_1x plugin for Wlan security control panel  
 */
//Class Declaration
class Cp802Dot1xUi : public QObject, public CpWlanSecurityPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpWlanSecurityPluginInterface)
    
    public:
        Cp802Dot1xUi();
        ~Cp802Dot1xUi();
    
    public:
        // from CpWlanSecurityPluginInterface 
    
        CMManagerShim::WlanSecMode securityMode() const;
            
        QString securityModeTextId() const;
            
        void setReference(CmConnectionMethodShim *cmCm, uint id);
            
        int orderNumber() const;
           
        CpSettingFormItemData* uiInstance(
                CpItemDataHelper &dataHelper);
        
        bool validateSettings();
    
    private:
    
        Q_DISABLE_COPY(Cp802Dot1xUi)      

        //!WPA security group item
        CpSettingFormItemData* mUi;   

        //!Translator for all the localisation Text Id's
        HbTranslator *mTranslator;

        //! Connection Settings Shim connection method pointer    
        CmConnectionMethodShim *mCmCM;    

        //! Eap Plugin config interface
        EapQtConfigInterface *mEapQtConfigInterface;

        //!802.1x ui Implementer Interface
        QScopedPointer <CpWpaCmnUi> m802Ui;

};

/*! @} */

#endif //CP802DOT1XUI_H
