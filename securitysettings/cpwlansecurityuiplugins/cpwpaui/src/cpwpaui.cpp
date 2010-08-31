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
 * %version: tr1cfwln#28 %
 */
//User Includes
#include "cpwpaui.h"
#include "cpwpacmnui.h"

// System includes
#include <QStringList>
#include <cmconnectionmethod_shim.h>
#include <cmmanagerdefines_shim.h>
#include <eapqtconfiginterface.h>
#include <HbTranslator>

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpauiTraces.h"
#endif

//Constants
//The order in which WPA/WPA2 only mode appears in the list of available 
//security modes
const int UI_ORDER_WPA_WPA2 = 20;
/*!
 \class CpWpaUi
 \brief CpWpaUi implements the common Ui for WPA/WPA2 
 Security Settings Control Panel Plugins,
 which will allow viewing/editing of WPA/WPA2 Security Settings.
 */
/*!
 * Constructor
 */
CpWpaUi::CpWpaUi() :
   mUi(NULL), 
   mTranslator(new HbTranslator("cpwlansecsettingsplugin")),
   mCmCM(NULL),
   mEapQtConfigInterface(NULL),
   mWpaUi(NULL)
{
    

}

//Destructor
CpWpaUi::~CpWpaUi()
{
    OstTraceFunctionEntry1(CPWPAUI_CPWPAUI_ENTRY,this);
    delete mEapQtConfigInterface;
    delete mTranslator;
    OstTraceFunctionExit1(CPWPAUI_CPWPAUI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========

/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWpaUi::securityMode() const
{
    OstTraceFunctionEntry1(CPWPAUI_SECURITYMODE_ENTRY,this);
    OstTraceFunctionExit1(CPWPAUI_SECURITYMODE_EXIT,this);
    //return security mode
    return CMManagerShim::WlanSecModeWpa;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_wpawpa2". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString CpWpaUi::securityModeTextId() const
{
    OstTraceFunctionEntry1( CPWPAUI_SECURITYMODETEXTID_ENTRY, this );
    OstTraceFunctionExit1( CPWPAUI_SECURITYMODETEXTID_EXIT, this );
    return "txt_occ_setlabel_wlan_security_mode_val_wpawpa2";
}

/*! 
 Sets the database reference IAP id.

 \param id Database reference
 */
void CpWpaUi::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceFunctionEntry1(CPWPAUI_SETREFERENCE_ENTRY,this);
    if (!mEapQtConfigInterface) {
       mEapQtConfigInterface = new EapQtConfigInterface(
               EapQtConfigInterface::EapBearerTypeWlan, id);
    } 
    else {
       mEapQtConfigInterface->setConfigurationReference(id);     
    }

    //mCmCM is not deleted assuming mCmManager owns it.
    mCmCM = cmCm;
    OstTraceFunctionExit1(CPWPAUI_SETREFERENCE_EXIT,this);
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int CpWpaUi::orderNumber() const
{
    OstTraceFunctionEntry1(CPWPAUI_ORDERNUMBER_ENTRY,this); 
    OstTraceFunctionExit1(CPWPAUI_ORDERNUMBER_EXIT,this);
    return UI_ORDER_WPA_WPA2;
}

/*!
 Creates an UI instance. Caller owns the object.
 
 \param dataHelper Item data helper
 \return Pointer to an UI object
 */
CpSettingFormItemData* CpWpaUi::uiInstance(CpItemDataHelper &dataHelper)
{
    OstTraceFunctionEntry1(CPWPAUI_UIINSTANCE_ENTRY,this);

		//reset the Common Ui Ptr
    mWpaUi.reset(new CpWpaCmnUi(CMManagerShim::WlanSecModeWpa, dataHelper));

    mUi = mWpaUi->createUi(mEapQtConfigInterface, mCmCM);
    
    OstTraceFunctionExit1(CPWPAUI_UIINSTANCE_EXIT,this);
    return mUi;
}

/*!
   Validates current security settings. This function is called whenever
   user tries to exit from the settings view. If the plugin determines
   that some settings need editing before considered valid, it shall
   return false. A dialog will be shown to the user indicating that
   settings are still incomplete and asking if he/she wishes to exit
   anyway.

   \return True if security settings for WPA/WPA2 are valid, false if not.
*/
bool CpWpaUi::validateSettings()
{
    return mWpaUi->validateSettings();
}

Q_EXPORT_PLUGIN2(CpWpaUi, CpWpaUi)
;
