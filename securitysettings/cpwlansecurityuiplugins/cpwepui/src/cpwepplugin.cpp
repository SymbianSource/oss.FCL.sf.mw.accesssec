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
 *    Control Panel QT UI for WEP configuration
 *
 */

/*
 * %version: 2 %
 */


//User Includes
#include "cpwepplugin.h"
#include "cpwepui.h"

// System includes
#include <cpitemdatahelper.h>
#include <cmconnectionmethod_shim.h>
#include <cmmanagerdefines_shim.h>
#include <HbTranslator>

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpweppluginTraces.h"
#endif

/*!
 \class CpWepPlugin
 \brief CpWepPlugin implements the WEP Security Settings Control Panel Plugin
 which allows viewing/editing of WEP Security Settings. CpWepPlugin class
 implements only interface to Control Panel, while the actual viewing/editing
 is implemented by CpWepUi class.
 */

// External function prototypes

// Local constants

//The order in which WEP only mode appears in the list of available 
//security mode
static const int UI_ORDER_WEP = 10;

Q_EXPORT_PLUGIN2(CpWepUi, CpWepPlugin);


// ======== LOCAL FUNCTIONS ========


// ======== MEMBER FUNCTIONS ========

/*!
 Contructs WEP plugin class
 */ 
CpWepPlugin::CpWepPlugin() :
    mTranslator(new HbTranslator("cpwlansecsettingsplugin")),
    mCmCM(NULL), 
    mCmId(0)    
{
    OstTrace0( TRACE_BORDER, DUP1_CPWEPPLUGIN_CPWEPPLUGIN, "CpWepPlugin::CpWepPlugin - create CpWepPlugin" );
    // Nothing is required
}

/*!
 Destructs WEP plugin class
 */
CpWepPlugin::~CpWepPlugin()
{
    OstTrace0( TRACE_BORDER, CPWEPPLUGIN_CPWEPPLUGIN, "CpWepPlugin::~CpWepPlugin - destroy CpWepPlugin" );
    
    // mCmCM is owned by CmManager and is not therefore
    // deleted.
    
    // mTranslator is protected by QScopedPointer and
    // is implicitly destroyed.
}

/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWepPlugin::securityMode() const
{
    OstTrace0( TRACE_BORDER, CPWEPPLUGIN_SECURITYMODE, "CpWepPlugin::securityMode - get security mode" );

    //return security mode
    return CMManagerShim::WlanSecModeWep;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_wep". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString CpWepPlugin::securityModeTextId() const
{
    OstTrace0( TRACE_BORDER, CPWEPPLUGIN_SECURITYMODETEXTID, "CpWepPlugin::securityModeTextId - get security mode text" );
    
    return "txt_occ_setlabel_wlan_security_mode_val_wep";
}

/*! 
 Sets the database reference.

 \param cmCM Handle to CM
 \param id Connection method ID
 */
void CpWepPlugin::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceExt2( TRACE_BORDER, CPWEPPLUGIN_SETREFERENCE, "CpWepPlugin::setReference - set database reference;cmCm=%p;id=%u", cmCm, id );
    
    mCmId = id;

    //mCmCM is not deleted assuming CmManager owns it.
    mCmCM = cmCm;
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int CpWepPlugin::orderNumber() const
{
    OstTrace0( TRACE_BORDER, CPWEPPLUGIN_ORDERNUMBER, "CpWepPlugin::orderNumber - get order number" );
    
    return UI_ORDER_WEP;
}

/*!
 Returns the fully constructed Ui Group , for WEP security plugin
  
 \param dataHelper for adding connections
  
 \return The WEP UI
 */
CpSettingFormItemData* CpWepPlugin::uiInstance(CpItemDataHelper &dataHelper)
{
    OstTraceExt1( TRACE_BORDER, CPWEPPLUGIN_UIINSTANCE, "CpWepPlugin::uiInstance - entry;mCmCM=%p", mCmCM );
    
    CpSettingFormItemData* ui = new CpWepUi(&dataHelper, mCmCM );

    OstTraceExt1( TRACE_BORDER, DUP1_CPWEPPLUGIN_UIINSTANCE, "CpWepPlugin::uiInstance - exit;ui=%p", ui );
    
    // Ownership of the ui moved to the caller
    return ui;
}


