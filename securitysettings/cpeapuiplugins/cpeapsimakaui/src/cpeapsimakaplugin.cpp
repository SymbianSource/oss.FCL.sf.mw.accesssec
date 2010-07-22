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
 *   Control Panel QT plugin for EAP-SIM and EAP-AKA 
 *   method configuration
 *
 */

/*
 * %version:  10 %
 */

// System includes
#include <eapqtpluginhandle.h>

// User includes
#include "cpeapsimakaplugin.h"
#include "cpeapsimakaui.h"
#include "eapuidefs.h"

/*!
 * \class CpEapSimAkaPlugin
 * \brief Control Panel QT plugin for EAP-SIM and EAP-AKA method configuration. 
 */

// External function prototypes

// Local constants

Q_EXPORT_PLUGIN2(CpEapSimAkaPlugin, CpEapSimAkaPlugin);

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 */
CpEapSimAkaPlugin::CpEapSimAkaPlugin() :
    mBearer(EapQtConfigInterface::EapBearerTypeWlan),
    mIapId(EapQtConfigInterface::IapIdUndefined)
{
    // Nothing to be done
    qDebug("CpEapSimAkaPlugin created");
}

/*!
 * Destructor.
 */
CpEapSimAkaPlugin::~CpEapSimAkaPlugin()
{
    // Nothing to be done
    // UI instances are owned and deallocated by CP framework
    qDebug("CpEapSimAkaPlugin destroyed");
}

/*!
 * See CpEapPluginInterface::setSettingsReference()
 * 
 * @param bearer Bearer of the accessed settings
 * @param iapId ID of the accessed IAP
 */
void CpEapSimAkaPlugin::setSettingsReference(const EapQtConfigInterface::EapBearerType bearer,
    const int iapId)
{
    mBearer = bearer;
    mIapId = iapId;
}

/*!
 * See CpEapPluginInterface::pluginInfo()
 * 
 * @return Plugin info (EAP-SIM and EAP-AKA)
 */
QList<EapQtPluginInfo> CpEapSimAkaPlugin::pluginInfo()
{
    qDebug("CpEapSimAkaPlugin: provide plugin info");
    QList<EapQtPluginInfo> ret;

    ret.append(EapQtPluginInfo(
        EapQtPluginHandle::PluginEapSim,
        EapQtUiConstants::StringEapSim,
        EapQtUiConstants::OrderEapSim));

    ret.append(EapQtPluginInfo(
        EapQtPluginHandle::PluginEapAka,
        EapQtUiConstants::StringEapAka,
        EapQtUiConstants::OrderEapAka));

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
 * @return SIM/AKA UI instance
 */
CpBaseSettingView* CpEapSimAkaPlugin::uiInstance(
    const EapQtPluginHandle& outerHandle,
    const EapQtPluginInfo &plugin)
{
    qDebug("CpEapSimAkaPlugin: create UI instance");

    Q_ASSERT(mIapId != EapQtConfigInterface::IapIdUndefined);

    // instance is owned and deallocated by CP framework
    return new CpEapSimAkaUi(mBearer, mIapId, plugin, outerHandle);
}
