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
 * %version: tr1cfwln#23 %
 */

// User includes
#include "cpwpa2ui.h"
#include "cpwpacmnui.h"

// System includes
#include <cmmanagerdefines_shim.h>
#include <cmconnectionmethod_shim.h>
#include <eapqtconfiginterface.h>
#include <QStringList>
#include <HbTranslator>

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpa2uiTraces.h"
#endif


// Constants
//The order in which WPA2 only mode appears in the list of available 
//security mode
const int UI_ORDER_WPA2_ONLY = 30;

/*!
 \class CpWpa2Ui
 \brief CpWpa2Ui implements the  Ui for WPA2 only 
 Security Settings Control Panel Plugin,
 which will allow viewing/editing of WPA2 only Security Settings.
 */
/*!
 * Constructor
 * 
 */
CpWpa2Ui::CpWpa2Ui() :
    mUi(NULL), 
    mTranslator(new HbTranslator("cpwlansecsettingsplugin")),
    mCmCM(NULL),
    mEapQtConfigInterface(NULL),
    mWpa2Ui(NULL)
{

}

//Destructor
CpWpa2Ui::~CpWpa2Ui()
{
    OstTraceFunctionEntry1(CPWPA2UI_CPWPA2UI_ENTRY,this);
    delete mEapQtConfigInterface;
    delete mTranslator;
    OstTraceFunctionExit1(CPWPA2UI_CPWPA2UI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========

/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWpa2Ui::securityMode() const
{
    OstTraceFunctionEntry1(CPWPA2UI_SECURITYMODE_ENTRY,this);
    OstTraceFunctionExit1(CPWPA2UI_SECURITYMODE_EXIT,this);
    //return security mode
    return CMManagerShim::WlanSecModeWpa2;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_wpa2_only". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString CpWpa2Ui::securityModeTextId() const
{
    OstTraceFunctionEntry1(CPWPA2UI_SECURITYMODETEXTID_ENTRY,this);
    OstTraceFunctionExit1(CPWPA2UI_SECURITYMODETEXTID_EXIT,this);
    return "txt_occ_setlabel_wlan_security_mode_val_wpa2_only";
}

/*! 
 Sets the database reference IAP id.

 \param id Database reference
 */
void CpWpa2Ui::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceFunctionEntry1(CPWPA2UI_SETREFERENCE_ENTRY,this);
    if (!mEapQtConfigInterface) {
        mEapQtConfigInterface = new EapQtConfigInterface(
            EapQtConfigInterface::EapBearerTypeWlan, id);
    } else {
        mEapQtConfigInterface->setConfigurationReference(id);     
    }

    //mCmCM is not deleted assuming mCmManager owns it.
    mCmCM = cmCm;
    OstTraceFunctionExit1(CPWPA2UI_SETREFERENCE_EXIT,this);
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int CpWpa2Ui::orderNumber() const
{
    OstTraceFunctionEntry1(CPWPA2UI_ORDERNUMBER_ENTRY,this);
    OstTraceFunctionExit1(CPWPA2UI_ORDERNUMBER_EXIT,this);
    return UI_ORDER_WPA2_ONLY;
}

/*!
 Creates an UI instance. Caller owns the object.
 
 \param dataHelper Item data helper
 \return Pointer to an UI object
 */
CpSettingFormItemData* CpWpa2Ui::uiInstance(CpItemDataHelper &dataHelpper)
{
    OstTraceFunctionEntry1(CPWPA2UI_UIINSTANCE_ENTRY,this);

	//reset the Common Ui Ptr
    mWpa2Ui.reset(new CpWpaCmnUi(CMManagerShim::WlanSecModeWpa2, dataHelpper));

    mUi = mWpa2Ui->createUi(mEapQtConfigInterface, mCmCM);
    
    OstTraceFunctionExit1(CPWPA2UI_UIINSTANCE_EXIT,this);
    return mUi;
}

/*!
   Validates current security settings. This function is called whenever
   user tries to exit from the settings view. If the plugin determines
   that some settings need editing before considered valid, it shall
   return false. A dialog will be shown to the user indicating that
   settings are still incomplete and asking if he/she wishes to exit
   anyway.

   \return True if security settings for WPA2 only are valid, false if not.
*/
bool CpWpa2Ui::validateSettings()
{
    return mWpa2Ui->validateSettings();
}


Q_EXPORT_PLUGIN2(CpWpa2Ui, CpWpa2Ui)
;
