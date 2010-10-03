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
 *   Control Panel QT plugin for TLS-based EAP methods configuration 
 *
 */

/*
 * %version:  8 %
 */

// System includes
#include <eapqtpluginhandle.h>

// User includes
#include "cpeaptlsmethodsplugin.h"
#include "cpeaptlsmethodsui.h"
#include "eapuidefs.h"

/*!
 * \class CpEapTlsMethodsPlugin
 * \brief Control Panel QT plugin for TLS-based EAP methods configuration. 
 */

// External function prototypes

// Local constants

Q_EXPORT_PLUGIN2(CpEapTlsMethodsPlugin, CpEapTlsMethodsPlugin);

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 */
CpEapTlsMethodsPlugin::CpEapTlsMethodsPlugin() :
    mBearer(EapQtConfigInterface::EapBearerTypeWlan),
    mIapId(EapQtConfigInterface::IapIdUndefined)
{
    // Nothing to be done

    qDebug("CpEapTlsMethodsPlugin created");
}

/*!
 * Destructor.
 */
CpEapTlsMethodsPlugin::~CpEapTlsMethodsPlugin()
{
    // Nothing to be done
    // UI instances are owned and deallocated by CP framework

    qDebug("CpEapTlsMethodsPlugin destroyed");
}

/*!
 * See CpEapPluginInterface::setSettingsReference()
 * 
 * @param bearer Bearer of the accessed settings
 * @param iapId ID of the accessed IAP
 */
void CpEapTlsMethodsPlugin::setSettingsReference(const EapQtConfigInterface::EapBearerType bearer,
    const int iapId)
{
    mBearer = bearer;
    mIapId = iapId;
}

/*!
 * See CpEapPluginInterface::pluginInfo()
 * 
 * @return Plugin info
 */
QList<EapQtPluginInfo> CpEapTlsMethodsPlugin::pluginInfo()
{
    qDebug("CpEapTlsMethodsPlugin: provide plugin info");
    QList<EapQtPluginInfo> ret;

    ret.append(EapQtPluginInfo(
        EapQtPluginHandle::PluginEapTtls,
        EapQtUiConstants::StringEapTtls,
        EapQtUiConstants::OrderEapTtls) );
    
    ret.append(EapQtPluginInfo(
        EapQtPluginHandle::PluginPeap,
        EapQtUiConstants::StringPeap,
        EapQtUiConstants::OrderPeap) );

    ret.append(EapQtPluginInfo(
        EapQtPluginHandle::PluginEapTls,
        EapQtUiConstants::StringEapTls,
        EapQtUiConstants::OrderEapTls) );

    ret.append(EapQtPluginInfo(
        EapQtPluginHandle::PluginEapFast,
        EapQtUiConstants::StringEapFast,
        EapQtUiConstants::OrderEapFast) );

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
 * @return TLS methods UI instance
 */
CpBaseSettingView* CpEapTlsMethodsPlugin::uiInstance(
    const EapQtPluginHandle& outerHandle,
    const EapQtPluginInfo &plugin)
{

    Q_ASSERT(mIapId != EapQtConfigInterface::IapIdUndefined);

    qDebug("CpEapTlsMethodsPlugin: create UI instance");
    return new CpEapTlsMethodsUi(mBearer, mIapId, plugin, outerHandle);
}
