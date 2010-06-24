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
 * %version: tr1cfwln#8 %
 */

//User Includes
#include "cp802dot1xui.h"
#include "cpwpacmnui.h"
#include "cpwpacmnui_global.h"

//System Includes
#include <cmmanagerdefines_shim.h>
#include <cmconnectionmethod_shim.h>
#include <eapqtconfiginterface.h>
#include <QStringList>
#include <HbTranslator>

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cp802dot1xuiTraces.h"
#endif

/*!
 \class Cp802Dot1xUi
 \brief Cp802Dot1xUi implements the common Ui for 802.1x only 
 Security Settings Control Panel Plugins,
 which will allow viewing/editing of 802.1x Security Settings.
 */
//The order in which 802_Dot_1x only mode appears in the list of available 
//security modes
const int UI_ORDER_802_Dot_1x = 40;

/*!
 * Constructor
 */

Cp802Dot1xUi::Cp802Dot1xUi() :
    mUi(NULL), 
    mTranslator(new HbTranslator("cpwlansecsettingsplugin")),
    mCmCM(NULL),
    mEapQtConfigInterface(NULL),
    m802Ui(NULL)
{
   
}

// Destructor
Cp802Dot1xUi::~Cp802Dot1xUi()
{
    OstTraceFunctionEntry1(CP802DOT1XUI_CP802DOT1XUI_ENTRY,this);
    delete mEapQtConfigInterface;
    delete mTranslator;
    OstTraceFunctionExit1(CP802DOT1XUI_CP802DOT1XUI_EXIT,this);
}

/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode Cp802Dot1xUi::securityMode() const
{
    OstTraceFunctionEntry1(CP802DOT1XUI_SECURITYMODE_ENTRY,this);
    OstTraceFunctionExit1(CP802DOT1XUI_SECURITYMODE_EXIT,this);
    //return security mode 
    return CMManagerShim::WlanSecMode802_1x;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_8021x". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString Cp802Dot1xUi::securityModeTextId() const
{
    OstTraceFunctionEntry1( CP802DOT1XUI_SECURITYMODETEXTID_ENTRY, this );
    OstTraceFunctionExit1( CP802DOT1XUI_SECURITYMODETEXTID_EXIT, this );
    return "txt_occ_setlabel_wlan_security_mode_val_8021x";
}

/*! 
 Sets the database reference IAP id.

 \param id Database reference
 */
void Cp802Dot1xUi::setReference(CmConnectionMethodShim *cmCm,uint id)
{
    OstTraceFunctionEntry1(CP802DOT1XUI_SETREFERENCE_ENTRY,this);    
    if (!mEapQtConfigInterface) {
           mEapQtConfigInterface = new EapQtConfigInterface(
               EapQtConfigInterface::EapBearerTypeWlan, id);
    } 
    else {
           mEapQtConfigInterface->setConfigurationReference(id);     
    }
    
    //mCmCM is not deleted assuming mCmManager owns it.
     mCmCM = cmCm;
    
    OstTraceFunctionExit1(CP802DOT1XUI_SETREFERENCE_EXIT,this);
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int Cp802Dot1xUi::orderNumber() const
{
    OstTraceFunctionEntry1(CP802DOT1XUI_ORDERNUMBER_ENTRY,this);
    OstTraceFunctionExit1(CP802DOT1XUI_ORDERNUMBER_EXIT,this);
    return UI_ORDER_802_Dot_1x;
}

/*!
 Creates an UI instance. Caller owns the object.
 
 \param dataHelper Item data helper
 \return Pointer to an UI object
 */
CpSettingFormItemData* Cp802Dot1xUi::uiInstance(CpItemDataHelper &dataHelpper)
{
    OstTraceFunctionEntry1(CP802DOT1XUI_UIINSTANCE_ENTRY,this);

    //reset Common Ui ptr
    m802Ui.reset(new CpWpaCmnUi(CMManagerShim::WlanSecMode802_1x, dataHelpper));
        
    mUi = m802Ui->createUi(mEapQtConfigInterface, mCmCM);
      
    OstTraceFunctionExit1(CP802DOT1XUI_UIINSTANCE_EXIT,this);
    return mUi;
}


/*!
   Validates current security settings. This function is called whenever
   user tries to exit from the settings view. If the plugin determines
   that some settings need editing before considered valid, it shall
   return false. A dialog will be shown to the user indicating that
   settings are still incomplete and asking if he/she wishes to exit
   anyway.

   \return True if security settings for 802.1x only are valid, false if not.
*/
bool Cp802Dot1xUi::validateSettings()
    {    
    return true;
    }


Q_EXPORT_PLUGIN2(Cp802Dot1xUi, Cp802Dot1xUi)
;
