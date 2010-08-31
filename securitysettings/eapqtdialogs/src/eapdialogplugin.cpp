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
* Description: Eap Dialog Plugin implementation
*
*/

/*
* %version: 10 %
*/

// System includes
#include <hbdevicedialoginterface.h>
#include <QVariantMap>

// User includes
#include "eapdialogplugin.h"
#include "eapusernamepwddialog.h"
#include "eapquerydialog.h"
#include "eappasswordquerydialog.h"
#include "eapfastinstallpacquerydialog.h"
#include "eapfastpacstorepwquerydialog.h"
#include "eapfastpacfilepwquerydialog.h"
#include "eapfastcreatemasterkeyquerydialog.h"
#include "eapfastprovwaitnotedialog.h"
#include "eapmschapv2pwdexpirednotedialog.h"
#include "eapmschapv2oldpwddialog.h"
#include "eapmschapv2newpwddialog.h"
#include "eapfastprovnotsuccessnotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "eapdialogpluginTraces.h"
#endif

/*!
 * \class EapDialogPlugin
 * \brief Implements Eap Dialog Plugin. 
 */

// External function prototypes

Q_EXPORT_PLUGIN2(eapdialogplugin, EapDialogPlugin)

// Local constants

//! This plugin implements several device dialog types
static const struct {
    const char *mTypeString;
} dialogInfos[] = {
    {"com.nokia.eap.usernamepassworddialog/1.0"},
    {"com.nokia.eap.querydialog/1.0"},
    {"com.nokia.eap.passwordquerydialog/1.0"},
    {"com.nokia.eap.fastinstallpacquerydialog/1.0"},
    {"com.nokia.eap.fastpacstorepwquerydialog/1.0"},
    {"com.nokia.eap.fastcreatemasterkeyquerydialog/1.0"},
    {"com.nokia.eap.fastpacfilepwquerydialog/1.0"},
    {"com.nokia.eap.fastprovwaitnotedialog/1.0"},
    {"com.nokia.eap.mschapv2passwordexpirednotedialog/1.0"},
    {"com.nokia.eap.mschapv2oldpassworddialog/1.0"},
    {"com.nokia.eap.mschapv2newpassworddialog/1.0"},
    {"com.nokia.eap.fastshowprovnotsuccessnotedialog/1.0"}
};

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 */
EapDialogPlugin::EapDialogPlugin()
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_EAPDIALOGPLUGIN_ENTRY );
    qDebug("EapDialogPlugin::EapDialogPlugin");
        
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_EAPDIALOGPLUGIN_EXIT );
}

/*!
 * Destructor
 */ 
EapDialogPlugin::~EapDialogPlugin()
{
    OstTraceFunctionEntry0( DUP1_EAPDIALOGPLUGIN_DEAPDIALOGPLUGIN_ENTRY );
      
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_DEAPDIALOGPLUGIN_EXIT );
}

/*!
 * Create device dialog widget
 *
 * @param [in]  deviceDialogType Tells which Dialog to create
 * @param [in]  parameters Parameters for the Construction of the dialog.
 * @return  created dialog widget
 */ 
HbDeviceDialogInterface *EapDialogPlugin::createDeviceDialog(
    const QString &deviceDialogType,
    const QVariantMap &parameters)
{  
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_CREATEDEVICEDIALOG_ENTRY );
    qDebug("EapDialogPlugin::createDeviceDialog ENTER");
    
    HbDeviceDialogInterface* dialog = NULL; 
        
    if ( deviceDialogType.compare(dialogInfos[0].mTypeString) == 0 ) 
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapUsernamePwdDialog");
        dialog = new EapUsernamePwdDialog(parameters);
        }
    else if ( deviceDialogType.compare(dialogInfos[1].mTypeString) == 0 ) 
        { 
        qDebug("EapDialogPlugin::createDeviceDialog: new EapQueryDialog");
        dialog = new EapQueryDialog(parameters);   
        }
    else if ( deviceDialogType.compare(dialogInfos[2].mTypeString) == 0 ) 
        { 
        qDebug("EapDialogPlugin::createDeviceDialog: new EapPasswordQueryDialog");
        dialog = new EapPasswordQueryDialog(parameters);
        }
    else if ( deviceDialogType.compare(dialogInfos[3].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastInstallPacQueryDialog");
        dialog = new EapFastInstallPacQueryDialog(parameters);
        }
    else if ( deviceDialogType.compare(dialogInfos[4].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastPacStorePwQueryDialog");
        dialog = new EapFastPacStorePwQueryDialog(parameters);
        }   
    else if ( deviceDialogType.compare(dialogInfos[5].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastCreateMasterKeyQueryDialog");
        dialog = new EapFastCreateMasterKeyQueryDialog(parameters);
        }  
    else if ( deviceDialogType.compare(dialogInfos[6].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastPacFilePwQueryDialog");
        dialog = new EapFastPacFilePwQueryDialog(parameters);
        }
    else if ( deviceDialogType.compare(dialogInfos[7].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastProvWaitNoteDialog");
        dialog = new EapFastProvWaitNoteDialog(parameters);
        }  
    else if ( deviceDialogType.compare(dialogInfos[8].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapMschapv2PwdExpNoteDialog");
        dialog = new EapMschapv2PwdExpNoteDialog(parameters);
        }  
    else if ( deviceDialogType.compare(dialogInfos[9].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapMschapv2OldPwdDialog");
        dialog = new EapMschapv2OldPwdDialog(parameters);
        }  
    else if ( deviceDialogType.compare(dialogInfos[10].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapMschapv2NewPwdDialog");
        dialog = new EapMschapv2NewPwdDialog(parameters);
        }  
    else if ( deviceDialogType.compare(dialogInfos[11].mTypeString) == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastProvNotSuccessNoteDialog");
        dialog = new EapFastProvNotSuccessNoteDialog(parameters);
        }   
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_CREATEDEVICEDIALOG_EXIT );
    qDebug("EapDialogPlugin::createDeviceDialog EXIT");
    
    return dialog;
}

/*!
 * Check if client is allowed to use device dialog widget. For the meantime
 * this plugin doesn't perform operations that may compromise security.
 * All clients are allowed to use.
 *
 * @param [in]  deviceDialogType Tells which Dialog type
 * @param [in]  parameters Device dialog parameters
 * @param [in]  securityInfo Information for Security check
 * @return  returns always true
 */ 
bool EapDialogPlugin::accessAllowed(const QString &deviceDialogType,
    const QVariantMap &parameters, const QVariantMap &securityInfo) const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_ACCESSALLOWED_ENTRY );
    
    Q_UNUSED(deviceDialogType)
    Q_UNUSED(parameters)
    Q_UNUSED(securityInfo)

    return true;
}

/*!
 * Return information of device dialog the plugin creates
 *
 * @param [in]  deviceDialogType Tells which Dialog type
 * @param [in]  parameters Device dialog parameters
 * @param [in,out]  info Structure the plugin fills with an information 
 * @return  returns always true
 */ 
bool EapDialogPlugin::deviceDialogInfo(const QString &deviceDialogType,
    const QVariantMap &parameters, DeviceDialogInfo *info) const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_DEVICEDIALOGINFO_ENTRY );
    qDebug("EapDialogPlugin::deviceDialogInfo");
    
    Q_UNUSED(parameters)
    Q_UNUSED(deviceDialogType)
    
    info->group = GenericDeviceDialogGroup;
    info->flags = NoDeviceDialogFlags;
    info->priority = DefaultPriority;
    
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_DEVICEDIALOGINFO_EXIT );
    qDebug("EapDialogPlugin::deviceDialogInfo EXIT");
    return true;
}

/*!
 * Returns a list of device dialog types the plugin implements. 
 *
 * @return returns device dialog types this plugin implements
 */ 
QStringList EapDialogPlugin::deviceDialogTypes() const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_DEVICEDIALOGTYPES_ENTRY );
    qDebug("EapDialogPlugin::deviceDialogTypes");
    
    QStringList types;
    const int numTypes = sizeof(dialogInfos) / sizeof(dialogInfos[0]);
    for(int i = 0; i < numTypes; i++) {
        types.append(dialogInfos[i].mTypeString);
    }
    
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_DEVICEDIALOGTYPES_EXIT );
    return types;
}

/*!
 * Return plugin flags
 *
 * @return returns plugin flags
 */ 
EapDialogPlugin::PluginFlags EapDialogPlugin::pluginFlags() const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_PLUGINFLAGS_ENTRY );   
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_PLUGINFLAGS_EXIT );
    return NoPluginFlags;
}

/*!
 * The last error is not stored, not supported
 *
 * @return returns always 0
 */ 
int EapDialogPlugin::error() const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_ERROR_ENTRY );
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_ERROR_EXIT );
    return 0;
}

