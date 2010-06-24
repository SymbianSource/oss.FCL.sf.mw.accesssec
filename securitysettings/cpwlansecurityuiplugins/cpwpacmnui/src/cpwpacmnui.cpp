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
 *    Control Panel QT UI for WPA/WPA2/802_Dot_1x configuration
 *
 */

/*
 * %version: tr1cfwln#23 %
 */

// System includes
#include <QStringList>
#include <cpsettingformitemdata.h>
#include <cpitemdatahelper.h>
#include <cpbasesettingview.h>
#include <cmconnectionmethod_shim.h>
#include <eapqtplugininfo.h>
#include <eapqtconfiginterface.h>

// User includes
#include "cpwpacmnui.h"
#include "cpwpacmnui_p.h"

// Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpacmnuiTraces.h"
#endif

/*!
 \class CpWpaCmnUi
 \brief CpWpaCmnUi implements the common Ui for WPA/WPA2/802.1x/WPA2 only 
 Security Settings Control Panel Plugins,
 which will allow viewing/editing of WPA/WPA2/802.1x/WPA2 Security Settings.
 */
//Contructs Common Ui (WPA/WPA2/802.1x/WPA2only) object
CpWpaCmnUi::CpWpaCmnUi(CMManagerShim::WlanSecMode securityMode, CpItemDataHelper &dataHelpper)
    
{
    d_ptr = new CpWpaCmnUiPrivate(securityMode,dataHelpper);
}
//Deletes objects owned by Common Ui
CpWpaCmnUi::~CpWpaCmnUi()
{
    //delete all dynamically allocated objects
    OstTraceFunctionEntry1(CPWPACMNUI_CPWPACMNUI_ENTRY,this);

    delete d_ptr;
    
   OstTraceFunctionExit1(CPWPACMNUI_CPWPACMNUI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========

/*!
 * Creates the Ui instance based on the security mode;WPAWPA2/802.1x/WPA2 only 
 * Owns the Ui instance
 * 
 * \param eapQtConfigInterface to list all eap plugins
 * \param mCmCM Connection MethoD Qt interface
 * 
 * \return Ui instance for the security mode set
 */

CpSettingFormItemData* CpWpaCmnUi::createUi(
        EapQtConfigInterface *eapQtConfigInterface,
        CmConnectionMethodShim *cmCM)
{
    OstTraceFunctionEntry1(CPWPACMNUI_CREATEUI_ENTRY,this);
    OstTraceFunctionExit1(CPWPACMNUI_CREATEUI_EXIT,this);    
    return d_ptr->createUi(eapQtConfigInterface,cmCM);
}


/*!
   Validates current security settings. This function is called whenever
   user tries to exit from the settings view. If the plugin determines
   that some settings need editing before considered valid, it shall
   return false. A dialog will be shown to the user indicating that
   settings are still incomplete and asking if he/she wishes to exit
   anyway.

   \return True if security settings are valid, false if not.
*/
bool CpWpaCmnUi::validateSettings()
    {
    return d_ptr->validateSettings();
    }





