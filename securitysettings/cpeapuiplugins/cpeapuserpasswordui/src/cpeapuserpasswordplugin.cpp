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
 *   Control Panel QT plugin for username-password based 
 *   EAP method configuration
 *
 */

/*
 * %version: 9 %
 */

// System includes
// User includes
#include "cpeapuserpasswordplugin.h"
#include "cpeapuserpasswordui.h"
#include "eapuidefs.h"

/*!
 * \class CpEapUserPasswordPlugin
 * \brief Control Panel QT plugin for username-password based EAP method configuration. 
 */

// External function prototypes

// Local constants

// Order numbers
static const int order_eapmschapv2(10);
static const int order_pap(20);
static const int order_plainmschapv2(30);
static const int order_eapgtc(40);
static const int order_leap(50);

Q_EXPORT_PLUGIN2(CpEapUserPasswordPlugin, CpEapUserPasswordPlugin)
;

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 */
CpEapUserPasswordPlugin::CpEapUserPasswordPlugin() :
    mBearer(EapQtConfigInterface::EapBearerTypeWlan),
    mIapId(EapQtConfigInterface::IapIdUndefined)
{
    // Nothing to be done

    qDebug("CpEapUserPasswordPlugin created");
}

/*!
 * Destructor.
 */
CpEapUserPasswordPlugin::~CpEapUserPasswordPlugin()
{
    // Nothing to be done
    // UI instances are owned and deallocated by CP framework

    qDebug("CpEapUserPasswordPlugin destroyed");
}

/*!
 * See CpEapPluginInterface::setSettingsReference()
 * 
 * @param bearer Bearer of the accessed settings
 * @param iapId ID of the accessed IAP
 */
void CpEapUserPasswordPlugin::setSettingsReference(
    const EapQtConfigInterface::EapBearerType bearer, const int iapId)
{
    mBearer = bearer;
    mIapId = iapId;
}

/*!
 * See CpEapPluginInterface::pluginInfo()
 * 
 * @return Plugin info
 */
QList<EapQtPluginInfo> CpEapUserPasswordPlugin::pluginInfo()
{
    qDebug("CpEapUserPasswordPlugin: provide plugin info");
    QList<EapQtPluginInfo> ret;

    ret.append(EapQtPluginInfo(EapQtPluginHandle::PluginEapMschapv2,  
        EapUiStrings::EapMschapv2, order_eapmschapv2) );
    
    ret.append(EapQtPluginInfo(EapQtPluginHandle::PluginPap, 
        EapUiStrings::Pap, order_pap) );

    ret.append(EapQtPluginInfo(EapQtPluginHandle::PluginPlainMschapv2,
        EapUiStrings::Mschapv2, order_plainmschapv2) );

    ret.append(EapQtPluginInfo(EapQtPluginHandle::PluginEapGtc, 
        EapUiStrings::EapGtc, order_eapgtc) );

    ret.append(EapQtPluginInfo(EapQtPluginHandle::PluginLeap, 
        EapUiStrings::Leap, order_leap) );

    return ret;
}

/*!
 * See CpEapPluginInterface::uiInstance()
 * 
 * Creates UI instance
 * 
 * @param outerHandle Plugin handle to outer EAP type.
 * @param plugin Plugin info
 * 
 * @return username-password UI instance
 */
CpBaseSettingView* CpEapUserPasswordPlugin::uiInstance(const EapQtPluginHandle& outerHandle,
    const EapQtPluginInfo &plugin)
{
    qDebug("CpEapUserPasswordPlugin: create UI instance");

    Q_ASSERT(mIapId != EapQtConfigInterface::IapIdUndefined);

    // instance is owned and deallocated by CP framework
    return new CpEapUserPasswordUi(mBearer, mIapId, plugin, outerHandle);
}
